/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 Yonatan Goldschmidt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

#include "get_fs_offset.h"


#define NUM_TAIL_CALLS 32
#define TOTAL_ITERS (MAX_TASK_STRUCT / sizeof(__u64))
#define ITERS_PER_PROG (TOTAL_ITERS / NUM_TAIL_CALLS)

// key - zero
// value - struct output
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct output);
} output SEC(".maps");

// key - tid
// value - expected fs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tid_to_fs SEC(".maps");

// key - tid
// value - current index into the task_struct
// only one entry because only one thread should reach the point that it's using this map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tid_to_index SEC(".maps");

// program array, to tail call into our program for "loops".
struct {
   __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
   __uint(max_entries, 1);
   __type(key, __u32);
   __type(value, __u32);
} progs SEC(".maps");

SEC("tp/syscalls/sys_enter_close")
int trigger(struct pt_regs *ctx)
{
    const __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *expected_fs_ptr = bpf_map_lookup_elem(&tid_to_fs, &tid);
    if (expected_fs_ptr == NULL) {
        return 0;
    }
    __u64 expected_fs = *expected_fs_ptr;

    const __u32 zero = 0;
    struct output out;
    unsigned int base;
    __u32 *index_ptr = bpf_map_lookup_elem(&tid_to_index, &tid);
    if (index_ptr == NULL) {
        base = 0; // first call
        out.offset = 0;
        out.status = STATUS_NOTFOUND;
    } else {
        base = *index_ptr;

        struct output *prev = bpf_map_lookup_elem(&output, &zero);
        if (prev == NULL) {
            // it's an error - we found a previous index but not a previous output struct?
            out.offset = 0;
            out.status = STATUS_ERROR;
            goto out;
        }
        out.offset = prev->offset;
        out.status = prev->status;
    }

    const __u64 *current = (__u64*)bpf_get_current_task();

    #pragma unroll
    for (unsigned int i = 0; i < ITERS_PER_PROG; i++) {
        unsigned long read_fs;
        int err = bpf_probe_read(&read_fs, sizeof(__u64), &current[base + i]);
        if (err != 0) {
            out.status = STATUS_ERROR;
            out.offset = err;
            goto out;
        }

        if (read_fs == expected_fs) {
            if (out.status != STATUS_NOTFOUND) {
                out.status = STATUS_DUP;
                goto out;
            }

            out.offset = (base + i) * sizeof(__u64);
            out.status = STATUS_OK;
            // continue searching, check for dups
        }
    }

    if (base + ITERS_PER_PROG < TOTAL_ITERS) {
        // tail call
        base += ITERS_PER_PROG;
        int err = bpf_map_update_elem(&tid_to_index, &tid, &base, BPF_ANY);
        if (err != 0) {
            out.status = STATUS_ERROR;
            out.offset = err;
            goto out;
        }

        err = bpf_map_update_elem(&output, &zero, &out, BPF_ANY);
        if (err != 0) {
            // :shrug:, next step ain't going to work anyway
            out.status = STATUS_ERROR;
            out.offset = err;
            goto out;
        }

        bpf_tail_call(ctx, &progs, 0);
        // if this call returns, it's an error.
        // oddly enough, the verifier wouldn't let me use the return value here...
        // (getting 'R0 !read_ok' for the next instruction after the call)
        // so I'm putting 0
        out.offset = 0;
        out.status = STATUS_ERROR;
        goto out;
    }

out:
    bpf_map_update_elem(&output, &zero, &out, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

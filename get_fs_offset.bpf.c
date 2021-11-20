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


// key - zero
// value - struct output
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
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

SEC("tp/syscalls/sys_enter_arch_prctl")
int do_arch_prctl(struct pt_regs *ctx)
{
    const __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *expected_fs_ptr = bpf_map_lookup_elem(&tid_to_fs, &tid);
    if (expected_fs_ptr == NULL) {
        return 0;
    }
    __u64 expected_fs = *expected_fs_ptr;

    struct output out;
    out.offset = 0;
    out.status = STATUS_NOTFOUND;

    const __u64 *current = (__u64*)bpf_get_current_task();

    #pragma unroll
    for (unsigned int i = 0; i < MAX_TASK_STRUCT / sizeof(__u64); i++) {
        unsigned long read_fs;
        int err = bpf_probe_read(&read_fs, sizeof(__u64), &current[i]);
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

            out.offset = i * sizeof(__u64);
            out.status = STATUS_OK;
            // continue searching, check for dups
        }
    }

out:;
    const __u8 zero = 0;
    bpf_map_update_elem(&output, &zero, &out, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

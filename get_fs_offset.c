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

#ifdef __x86_64__
#include <asm/prctl.h>
#include <sys/prctl.h>
#endif

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "get_fs_offset.skel.h"
#include "get_fs_offset.h"


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static __u64 get_tls_base(void) {
    __u64 fs;

#ifdef __x86_64__
    // at first I tried using ARCH_SET_FS to some arbitrary value which the BPF program will expect,
    // but it messes up with glibc (quite expectedly...)
    // so we'll use its real value instead.
    if (syscall(__NR_arch_prctl, ARCH_GET_FS, &fs)) {
        fprintf(stderr, "failed to arch_prctl(ARCH_GET_FS): %d\n", errno);
        return 1;
    }
#elif defined(__aarch64__)
    __asm__ ("mrs %0,tpidr_el0" : "=r"(fs));
#else
#error "unknown arch"
#endif

    return fs;
}

static int thread_func(void) {
    struct get_fs_offset_bpf *obj = get_fs_offset_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    int err = get_fs_offset_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto out;
    }

    err = get_fs_offset_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF program: %d\n", err);
        goto out;
    }

    const __u64 fs = get_tls_base();

    const __u32 tid = syscall(__NR_gettid);
    int tid_to_fs_fd = bpf_map__fd(obj->maps.tid_to_fs);
    if ((err = bpf_map_update_elem(tid_to_fs_fd, &tid, &fs, BPF_NOEXIST)) < 0) {
        fprintf(stderr, "failed to insert TID entry: %d\n", err);
        goto out;
    }

    const __u32 zero = 0;
    int progs_fd = bpf_map__fd(obj->maps.progs);
    __u32 prog_fd = bpf_program__fd(obj->progs.trigger);
    if ((err = bpf_map_update_elem(progs_fd, &zero, &prog_fd, BPF_ANY)) < 0) {
        fprintf(stderr, "failed to insert program entry: %d (prog fd: %d)\n", err, prog_fd);
        goto out;
    }

    // trigger the bpf program - we've just attached to the tracepoint on this function.
    (void)syscall(__NR_close, -1);

    int output_fd = bpf_map__fd(obj->maps.output);
    struct output output;
    if ((err = bpf_map_lookup_elem(output_fd, &zero, &output)) < 0) {
        fprintf(stderr, "failed to lookup output map: %d\n", err);
        goto out;
    }

    switch (output.status) {
    case STATUS_OK:
        printf("%u\n", output.offset);
        break;

    case STATUS_ERROR:
        fprintf(stderr, "had an error: %d\n", (int)output.offset);
        err = 1;
        break;

    case STATUS_NOTFOUND:
        fprintf(stderr, "fs not found, searched for %u bytes into task_struct\n", MAX_TASK_STRUCT);
        err = 1;
        break;

    case STATUS_DUP:
        fprintf(stderr, "found multiple matching offsets!\n");
        err = 1;
        break;

    default:
        fprintf(stderr, "unknwon status %d\n", output.status);
        err = 1;
        break;
    }

out:
    get_fs_offset_bpf__destroy(obj);
    return err != 0;
}

int main(int argc, const char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--verbose") == 0) {
        libbpf_set_print(libbpf_print_fn);
    }

    // on Aarch64, the TLS value (as read by get_tls_base()) appears to be inconsistent
    // on the main thread. that is, if thread_func() is ran on the main thread, it works non
    // deterministically, as if something is messing with the TLS value of the main thread?
    // on a spawned thread it works determinstically, so meh.
    pthread_t thread;
    int ret;
    pthread_create(&thread, NULL, (void*(*)(void*))thread_func, NULL);
    pthread_join(thread, (void**)&ret);
    return ret;
}

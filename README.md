## get_fs_offset

This tiny BPF program & driver can be used to determine the offset of `task_struct->thread.fs` (or `fsbase`, depending on your kernel version) in runtime, without using kernel headers.

While working on [PyPerf](https://github.com/Granulate/bcc), which is a complex BPF program whose only dependency on kernel structs is on `task_struct->thread.fs`, I wanted to lift that kernel headers dependency. This logic to find the offset in runtime could help (although I later found out that BCC *itself* depends on kernel headers; that'll be solved elseways...)

It was also my first libbpf-based program, so I took it as a fun training :)

### How it works

The driver program reads its thread's `fs` value, sets it as the expected value for the BPF program, and loads it.

The BPF program is triggered (by the "arbitrary" tracepoint on `close`). It scans the current `task_struct`'s memory for 16kb, finding pointers that match the expected `fs` value.

The driver then reports the found offset, or the error (none found / found more than 1 / `bpf_probe_read` error).

#### Aarch64 support

It works for Aarch64 as well, although there it actually scans for `task_struct->thread.tp_value`, but I still use the `fs` notation :shrug:

### Tested versions

x86_64: Some kernels from 4.14 to 5.11.

Aarch64: 5.13

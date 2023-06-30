// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
	u64 id;
	pid_t pid;
	int ret;
	struct event e;

    memset(&e.entries, 0, sizeof(e.entries));
    ret = bpf_get_branch_snapshot(&e.entries,
                                  sizeof(e.entries) / sizeof(e.entries[0]),
                                  0);
    if (ret > 0)
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
}

char LICENSE[] SEC("license") = "GPL";

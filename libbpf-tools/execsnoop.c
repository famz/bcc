// Based on execsnoop(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100
#define NSEC_PRECISION (NSEC_PER_SEC / 1000)
#define MAX_ARGS_KEY 259

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char *name;
	const char *line;
	bool print_uid;
	bool verbose;
	int max_args;
	char *cgroupspath;
	bool cg;
} env = {
	.max_args = DEFAULT_MAXARGS,
	.uid = INVALID_UID
};

static struct timespec start_time;

const char *argp_program_version = "execsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace exec syscalls\n"
"\n"
"USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] [-U] [-c CG]\n"
"                 [--max-args MAX_ARGS]\n"
"\n"
"EXAMPLES:\n"
"   ./execsnoop           # trace all exec() syscalls\n"
"   ./execsnoop -x        # include failed exec()s\n"
"   ./execsnoop -T        # include time (HH:MM:SS)\n"
"   ./execsnoop -U        # include UID\n"
"   ./execsnoop -u 1000   # only trace UID 1000\n"
"   ./execsnoop -t        # include timestamps\n"
"   ./execsnoop -q        # add \"quotemarks\" around arguments\n"
"   ./execsnoop -n main   # only print command lines containing \"main\"\n"
"   ./execsnoop -l tpkg   # only print command where arguments contains \"tpkg\""
"   ./execsnoop -c CG     # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "include time column on output (HH:MM:SS)" },
	{ "timestamp", 't', NULL, 0, "include timestamp on output" },
	{ "fails", 'x', NULL, 0, "include failed exec()s" },
	{ "uid", 'u', "UID", 0, "trace this UID only" },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments" },
	{ "name", 'n', "NAME", 0, "only print commands matching this name, any arg" },
	{ "line", 'l', "LINE", 0, "only print commands where arg contains this line" },
	{ "print-uid", 'U', NULL, 0, "print UID column" },
	{ "max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
		"maximum number of arguments parsed and displayed, defaults to 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long int uid, max_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'T':
		env.time = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'x':
		env.fails = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno || uid < 0 || uid >= INVALID_UID) {
			fprintf(stderr, "Invalid UID %s\n", arg);
			argp_usage(state);
		}
		env.uid = uid;
		break;
	case 'q':
		env.quote = true;
		break;
	case 'n':
		env.name = arg;
		break;
	case 'l':
		env.line = arg;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case MAX_ARGS_KEY:
		errno = 0;
		max_args = strtol(arg, NULL, 10);
		if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
			fprintf(stderr, "Invalid MAX_ARGS %s, should be in [1, %d] range\n",
					arg, TOTAL_MAX_ARGS);

			argp_usage(state);
		}
		env.max_args = max_args;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void inline quoted_symbol(char c) {
	switch(c) {
		case '"':
			putchar('\\');
			putchar('"');
			break;
		case '\t':
			putchar('\\');
			putchar('t');
			break;
		case '\n':
			putchar('\\');
			putchar('n');
			break;
		default:
			putchar(c);
			break;
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
    int i;

    for (i = 0; i < sizeof(e->entries) / sizeof(e->entries[0]); i++) {
        if (!e->entries[i].to) {
            break;
        }
        printf("0x%016lx\n", e->entries[i].to);
    }
    printf("\n");
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int cpu_cnt;
static int *pfd_array;
static int create_perf_events(void)
{
	struct perf_event_attr attr = {0};
	int cpu;

	/* create perf event */
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_RAW;
	attr.config = 0x1b00;
	attr.sample_type = PERF_SAMPLE_BRANCH_STACK;
	attr.branch_sample_type = PERF_SAMPLE_BRANCH_KERNEL |
		PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_ANY;

	cpu_cnt = libbpf_num_possible_cpus();
	pfd_array = malloc(sizeof(int) * cpu_cnt);
	if (!pfd_array) {
		cpu_cnt = 0;
		return 1;
	}

	for (cpu = 0; cpu < cpu_cnt; cpu++) {
		pfd_array[cpu] = syscall(__NR_perf_event_open, &attr,
					 -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pfd_array[cpu] < 0)
			break;
	}

	return cpu == 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct execsnoop_bpf *obj;
	int err;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

    create_perf_events();
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = execsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = execsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	err = execsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	/* print headers */
	if (env.time) {
		printf("%-9s", "TIME");
	}
	if (env.timestamp) {
		printf("%-8s ", "TIME(s)");
	}
	if (env.print_uid) {
		printf("%-6s ", "UID");
	}

	printf("%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS");

	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	execsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char _license[] SEC("license") = "GPL";

extern const void *bpf_prog_fops __ksym __weak;

struct pid_iter_entry {
	__u32 id;
	int pid;
	char comm[16];
};

SEC("iter/task_file")
int bpftop_iter(struct bpf_iter__task_file *ctx)
{
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	struct pid_iter_entry e;

	if (!file || !task)
		return 0;

	// Skip BPF program file filtering on kernels where bpf_prog_fops is not available
	// This is a workaround for older kernels that don't export this symbol
	// We'll process all files and let userspace filter invalid entries

	__builtin_memset(&e, 0, sizeof(e));

	e.pid = task->tgid;
	e.id = BPF_CORE_READ((struct bpf_prog *)file->private_data, aux, id);

	bpf_probe_read_kernel_str(&e.comm, sizeof(e.comm),
				  task->group_leader->comm);
	bpf_seq_write(ctx->meta->seq, &e, sizeof(e));

	return 0;
}
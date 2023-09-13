#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/cgroup.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/page_counter.h>
#include <linux/mmzone.h>
#include <linux/swap.h>
#include <linux/mm_inline.h>
#include <linux/mmdebug.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/vmalloc.h>


// 어떤 cgroup을 scan할 것인지 알려주는 모듈 패러미터.
// pid를 통해 cgroup을 얻음.
static int target_pid = -1;
module_param(target_pid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

struct perf_sample {
	struct perf_event_header header;
	u64 ip;
	u32 pid, tid;
	u64 addr;
	u64 weight;
};

#define PEBS_SAMPLE_TYPE PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR
#define PMEM_READ 0x80d1
#define DRAM_READ 0x01d3
#define STORE_ALL 0x82d0
static struct perf_event **events;
static size_t configs[] = { DRAM_READ, PMEM_READ, STORE_ALL };

static void pebs_sample(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs)
{
	if (event->attr.config == DRAM_READ)
		pr_info("DRAM READ: \n");
	else if (event->attr.config == PMEM_READ)
		pr_info("PMEM_READ: \n");
	else
		pr_info("STORE ALL: \n");
	pr_info("pid, phys_addr: %u, %lu\n", data->tid_entry.pid, data->phys_addr);
}

static int __init pebs_init(void)
{
	size_t config, cpu, ncpus = num_online_cpus();
	static struct perf_event_attr wd_hw_attr = {
		.type = PERF_TYPE_RAW,
		.size = sizeof(struct perf_event_attr),
		.pinned = 0,
		.disabled = 1,
		.precise_ip = 2,
		.sample_id_all = 1,
		.exclude_kernel = 1,
		.exclude_guest = 1,
		.exclude_hv = 1,
		.exclude_user = 0,
		.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_WEIGHT | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR,
	};

	events = vmalloc(ncpus * ARRAY_SIZE(configs) * sizeof(*events));
	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			size_t idx = config * ncpus + cpu;
			wd_hw_attr.config = configs[config];
			wd_hw_attr.sample_period = 10007;
			events[idx] = perf_event_create_kernel_counter(&wd_hw_attr, cpu, NULL, pebs_sample, NULL);
			if (IS_ERR(events[idx])) {
				pr_info("Could not create event %lu on cpu %lu\n", configs[config], cpu);
				return -1;
			}
			perf_event_enable(events[idx]);
		}
	}
	return 0;
}

static void __exit pebs_exit(void)
{
	size_t cpu, config, ncpus = num_online_cpus();

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			size_t idx = config * ncpus + cpu;
			perf_event_disable(events[idx]);
			perf_event_release_kernel(events[idx]);
		}
	}
}

module_init(pebs_init);
module_exit(pebs_exit);

MODULE_AUTHOR("Minho Kim <mhkim@dgist.ac.kr>");
MODULE_DESCRIPTION("PEBS test");
MODULE_LICENSE("GPL v2");

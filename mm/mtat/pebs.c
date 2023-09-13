// SPDX-License-Identifier: GPL-2.0
/*
 * Page Access Monitoring using PEBS
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#define pr_fmt(fmt) "pebs: " fmt

#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/pid.h>
#include <linux/cgroup.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mmzone.h>
#include <linux/swap.h>
#include <linux/mm_inline.h>
#include <linux/mmdebug.h>
#include <linux/rmap.h>
#include <linux/jiffies.h>
#include <linux/pagewalk.h>
#include <linux/mmu_notifier.h>
#include <linux/kthread.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>
#include <linux/perf_event.h>
#include <linux/mtat.h>

#include "../internal.h"
#include "pebs.h"

/*
 * PEBS related variables and functions
 */
static struct perf_event **events;
static size_t configs[] = { DRAM_READ, PMEM_READ, STORE_ALL };
static void perf_start(void);
static void perf_stop(void);
static void pebs_sample(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs);

static struct rhashtable *count_table = NULL;
static struct rhashtable_params params = {
	.head_offset = offsetof(struct access_counter, node),
	.key_offset = offsetof(struct access_counter, pfn),
	.key_len = sizeof(unsigned long),
	.automatic_shrinking = true,
	.min_size = 0xffff,
};

/* 
 * count_table structure's methods
 */
static void rh_free_fn(void *ptr, void *arg)
{
	struct access_counter *counter = ptr;
	kfree(counter);
}

static struct task_struct *kpebsd;
static int kpebsd_fn(void *data);

struct pebs_ctx *pebs_new_ctx(int nr_pids)
{
	struct pebs_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		goto err;

	ctx->pids = kzalloc(sizeof(int) * nr_pids, GFP_KERNEL);
	if (!ctx->pids)
		goto free_ctx;
	ctx->mms = kzalloc(sizeof(*ctx->mms) * nr_pids, GFP_KERNEL);
	if (!ctx->mms)
		goto free_pids;

	mutex_init(&ctx->pebs_lock);
	ctx->nr = nr_pids;
	ctx->running = false;

	return ctx;

free_pids:
	kfree(ctx->pids);
free_ctx:
	kfree(ctx);
err:
	return NULL;
}

void pebs_destroy_ctx(struct pebs_ctx *ctx)
{
	kfree(ctx->pids);
	kfree(ctx->mms);
	kfree(ctx);
}

int pebs_start(struct pebs_ctx *ctx)
{
	int err = -EBUSY;
	unsigned long flags;
	int i;
	struct mm_struct *mm;

	if (node_state(1, N_MEMORY)) {
		count_table = kmalloc_node(sizeof(*count_table), GFP_NOWAIT, 1);
	} else { 
		count_table = kmalloc(sizeof(*count_table), GFP_NOWAIT);
	}
	if (!count_table){
		pr_err("Failed to allocate count_table\n");
		return -ENOMEM;
	}

	err = rhashtable_init(count_table, &params);
	if (err) {
		pr_err("Failed to init rhashtable\n");
		return err;
	}

	mutex_lock(&ctx->pebs_lock);
	
	for (i = 0; i < ctx->nr; i++) {
		mm = ctx->mms[i];
		// bucket_sort 할당 진행
		spin_lock_irqsave(&mm->bucket_lock, flags);

		// 이 때, target_mm의 bucket_sort는 무조건 NULL이어야 함.
		if (mm->bucket_sort_arr) {
			spin_unlock_irqrestore(&mm->bucket_lock, flags);
			mutex_unlock(&ctx->pebs_lock);
			pr_err("bucket sort already exists!");
			return -EINVAL;
		}
	
		// 할당 및 초기화 진행
		mm->bucket_sort_arr = alloc_bucket_sort_array();
		if (!mm->bucket_sort_arr) {
			spin_unlock_irqrestore(&mm->bucket_lock, flags);
			mutex_unlock(&ctx->pebs_lock);
			pr_err("Failed to allocate bucket_sort");
			return -ENOMEM;
		}
		bucket_init_array(mm->bucket_sort_arr);
		spin_unlock_irqrestore(&mm->bucket_lock, flags);
	}

	ctx->running = true;

	perf_start();

	pr_info("pebs started\n");

	kpebsd = kthread_run(kpebsd_fn, ctx, "kpebsd");
	if (IS_ERR(kpebsd)) {
		err = PTR_ERR(kpebsd);
		kpebsd = NULL;
	}
	mutex_unlock(&ctx->pebs_lock);

	return err;
}

int pebs_stop(struct pebs_ctx *ctx)
{
	int i;
	unsigned long flags;
	struct mm_struct *mm;

	kthread_stop(kpebsd);
	for (;;) {
		mutex_lock(&ctx->pebs_lock);
		if (!kpebsd) {
			mutex_unlock(&ctx->pebs_lock);
			break;
		}
		mutex_unlock(&ctx->pebs_lock);
	}

	mutex_lock(&ctx->pebs_lock);

	perf_stop();

	for (i = 0; i < ctx->nr; i++) {
		mm = ctx->mms[i];

		spin_lock_irqsave(&mm->bucket_lock, flags);
		destroy_bucket_sort_array(mm->bucket_sort_arr);
		mm->bucket_sort_arr = NULL;
		spin_unlock_irqrestore(&mm->bucket_lock, flags);
	}

	rhashtable_free_and_destroy(count_table, rh_free_fn, NULL);
	kfree(count_table);
	count_table = NULL;

	ctx->running = false;

	mutex_unlock(&ctx->pebs_lock);

	pr_info("pebs stopped\n");

	return 0;
}

static int kpebsd_fn(void *data)
{
	struct pebs_ctx *ctx = data;
	struct mm_struct *mm;
	int i;
	unsigned long flags;
	
	pr_info("kpebsd start\n");
	while (!kthread_should_stop()) {
		for (i = 0; i < ctx->nr; i++) {
			mm = ctx->mms[i];
			spin_lock_irqsave(&mm->bucket_lock, flags);
			print_bucket_sort_array(mm->bucket_sort_arr);
			spin_unlock_irqrestore(&mm->bucket_lock, flags);
		}
		ssleep(5);
	}

	mutex_lock(&ctx->pebs_lock);
	kpebsd = NULL;
	mutex_unlock(&ctx->pebs_lock);
	pr_info("kpebsd stop\n");

	return 0;
}

static void perf_start(void)
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
		.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | 
					   PERF_SAMPLE_WEIGHT | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR,
	};

	if (node_state(1, N_MEMORY)) {
		events = vmalloc_node(ncpus * ARRAY_SIZE(configs) * sizeof(*events), 1);
	} else {
		events = vmalloc(ncpus * ARRAY_SIZE(configs) * sizeof(*events));
	}
	if (!events) {
		pr_err("failed to allocate perf_event\n");
		return;
	}

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			size_t idx = config * ncpus + cpu;
			wd_hw_attr.config = configs[config];
			wd_hw_attr.sample_period = SAMPLE_PERIOD_PEBS;
			events[idx] = 
				perf_event_create_kernel_counter(&wd_hw_attr, cpu, NULL, pebs_sample, NULL);
			if (IS_ERR(events[idx])) {
				pr_err("failed to create event %lu on cpu %lu\n", configs[config], cpu);
				return;
			}
			perf_event_enable(events[idx]);
		}
	}
}

static void perf_stop(void)
{
	size_t config, cpu, ncpus = num_online_cpus();

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			size_t idx = config * ncpus + cpu;
			perf_event_disable(events[idx]);
			perf_event_release_kernel(events[idx]);
		}
	}

	vfree(events);
}

static void pebs_sample(struct perf_event *event, 
		struct perf_sample_data *data, struct pt_regs *regs)
{
	unsigned long pfn, flags;
	int nid, err;
	struct access_counter *counter = NULL;
	struct bucket_sort *bucket_sort = NULL;
	bool write = event->attr.config == STORE_ALL;
	struct mm_struct *mm = ptscan_get_mm(data->tid_entry.pid);

	if (!mm)
		return;

	spin_lock_irqsave(&mm->bucket_lock, flags);
	if (!mm->bucket_sort_arr) {
		spin_unlock_irqrestore(&mm->bucket_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&mm->bucket_lock, flags);
	
	pfn = data->phys_addr >> PAGE_SHIFT;
	nid = page_to_nid(pfn_to_page(pfn));
	if (nid > 1) {
		pr_err("nid(%d) > 2 !!!\n", nid);
		nid = 1;
	}

	spin_lock_irqsave(&mm->bucket_lock, flags);
	bucket_sort = mm->bucket_sort_arr[nid];

	counter = rhashtable_lookup_fast(count_table, &pfn, params);
	if (!counter) {
		counter = new_access_counter(pfn, mm);
		if (!counter) {
			pr_err("Failed to allocate access_counter\n");
			goto out;
		}
		if (write)
			inc_access_counter(counter);

		err = rhashtable_insert_fast(count_table, &counter->node, params);
		if (err) {
			pr_err("Failed to insert access_counter into count_table\n");
			kfree(counter);
			goto out;
		}

		bucket_insert_counter(bucket_sort, counter);
	} else {
		counter->count >>= (mm->cool_clock - counter->cool_clock);
		counter->cool_clock = mm->cool_clock;
		if (counter->count >= cool_threshold)
			mm->cool_clock += 1;

		inc_access_counter(counter);
		if (write)
			inc_access_counter(counter);

		bucket_reinsert(bucket_sort, counter);
	}

out:
	spin_unlock_irqrestore(&mm->bucket_lock, flags);
}

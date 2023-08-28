// SPDX-License-Identifier: GPL-2.0
/*
 * Page Table Scanner
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#define pr_fmt(fmt) "ptscan: " fmt

#include <linux/slab.h>
#include <linux/kthread.h>
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
#include <linux/ptscan.h>

#include "../internal.h"

// ptscan 내부 전역 변수 count table로 pfn들의 access count를 저장.
// kptscand 들끼리 공유함, 따라서 ptscan_lock으로 보호 필요.
struct rhashtable *count_table = NULL;
struct rhashtable_params params = {
	.head_offset = offsetof(struct access_counter, node),
	.key_offset = offsetof(struct access_counter, pfn),
	.key_len = sizeof(unsigned long),
	.automatic_shrinking = true,
};

static int nr_running_ctxs = 0;
// nr_running_ctxs, count_table 보호용 락.
// page free할 때는 절대 이 락을 잡으면 안됨. 잡으면 데드락 발생.
// mm의 bucket_lock도 마찬가지.
DEFINE_SPINLOCK(ptscan_lock);

struct ptscan_ctx *ptscan_new_ctx(void)
{
	struct ptscan_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	mutex_init(&ctx->kptscand_lock);

	return ctx;
}

void ptscan_destroy_ctx(struct ptscan_ctx *ctx)
{
	kfree(ctx);
}

static int kptscand_fn(void *data);
static struct mm_struct *ptscan_get_mm(int target_pid);
static struct bucket_sort *alloc_bucket_sort(void);

int ptscan_start(struct ptscan_ctx *ctx)
{
	int err = -EBUSY;
	unsigned long flags;
	struct mm_struct *mm;

	spin_lock_irqsave(&ptscan_lock, flags);
	if (!nr_running_ctxs) {
		count_table = kmalloc(sizeof(*count_table), GFP_KERNEL);
		err = rhashtable_init(count_table, &params);
		if (err) {
			spin_unlock_irqrestore(&ptscan_lock, flags);
			pr_err("Failed to init rhashtable\n");
			return err;
		}
	}
	nr_running_ctxs++;
	spin_unlock_irqrestore(&ptscan_lock, flags);

	mutex_lock(&ctx->kptscand_lock);
	// pid를 이용하여 mm_struct 획득.
	ctx->target_mm = ptscan_get_mm(ctx->pid);
	if (!ctx->target_mm) {
		pr_err("Failed to get mm_struct");
		mutex_unlock(&ctx->kptscand_lock);
		return -EINVAL;
	}
	mm = ctx->target_mm;
	
	// bucket_sort 할당 진행
	spin_lock_irqsave(&mm->bucket_lock, flags);

	// 이 때, target_mm의 bucket_sort는 무조건 NULL이어야 함.
	if (mm->bucket_sort) {
		spin_unlock_irqrestore(&mm->bucket_lock, flags);
		mutex_unlock(&ctx->kptscand_lock);
		pr_err("bucket sort already exists!");
		return -EINVAL;
	}
	
	// 할당 및 초기화 진행
	mm->bucket_sort = alloc_bucket_sort();
	if (!mm->bucket_sort) {
		spin_unlock_irqrestore(&mm->bucket_lock, flags);
		mutex_unlock(&ctx->kptscand_lock);
		pr_err("Failed to allocate bucket_sort");
		return -ENOMEM;
	}
	bucket_init(mm->bucket_sort);
	spin_unlock_irqrestore(&mm->bucket_lock, flags);

	// kptscand 시작.
	if (!ctx->kptscand) {
		err = 0;
		ctx->kptscand = kthread_run(kptscand_fn, ctx, "kptscand.%d",
				nr_running_ctxs-1);
		if (IS_ERR(ctx->kptscand)) {
			err = PTR_ERR(ctx->kptscand);
			ctx->kptscand = NULL;
		}
	}
	mutex_unlock(&ctx->kptscand_lock);

	return err;
}

int ptscan_stop(struct ptscan_ctx *ctx)
{
	struct task_struct *tsk;

	mutex_lock(&ctx->kptscand_lock);
	tsk = ctx->kptscand;
	if (tsk) {
		get_task_struct(tsk);
		mutex_unlock(&ctx->kptscand_lock);
		kthread_stop(tsk);
		put_task_struct(tsk);
		return 0;
	}
	mutex_unlock(&ctx->kptscand_lock);

	return -EPERM;
}

/* 
 * access_counter structure's methods
 */
static struct access_counter *new_access_counter(unsigned long pfn, struct mm_struct *mm)
{
	struct access_counter *counter = NULL;
	counter = kmalloc(sizeof(*counter), GFP_KERNEL);
	if (!counter)
		return NULL;
	counter->pfn = pfn;
	counter->count = 1;
	counter->bucket_idx = 0;
	INIT_LIST_HEAD(&counter->list);
	counter->target_mm = mm;
	return counter;
}

static void destroy_access_counter(struct access_counter *counter)
{
	kfree(counter);
}

static void inc_access_counter(struct access_counter *counter)
{
	if (counter->count < MAX_ACCESS_COUNTER_VALUE)
		counter->count++;
}

/* 
 * bucket_sort structure's methods
 */
static int get_bucket_index(unsigned long count)
{
	int i;

	if (count > MAX_ACCESS_COUNTER_VALUE)
		count = MAX_ACCESS_COUNTER_VALUE;

	for (i = 0; i < NR_BUCKETS; i++) {
		if (count > i && count <= (i+1))
			break;
	}
	return i;
}

static struct bucket_sort *alloc_bucket_sort(void)
{
	struct bucket_sort *bucket_sort = NULL;
	bucket_sort = kmalloc(sizeof(*bucket_sort), GFP_KERNEL);
	
	return bucket_sort;
}

static void destroy_bucket_sort(struct bucket_sort *bucket_sort)
{
	kfree(bucket_sort);
}

void bucket_init(struct bucket_sort *bucket_sort)
{
	int i;
	for (i = 0; i < NR_BUCKETS; i++) {
		bucket_sort->counts[i] = 0;
		INIT_LIST_HEAD(&bucket_sort->buckets[i]);
	}
}

void bucket_remove_page(struct page *page)
{
	unsigned long pfn = page_to_pfn(page);
	struct access_counter *counter;
	struct mm_struct *mm;
	unsigned long flags;

	spin_lock_irqsave(&ptscan_lock, flags);
	if (!count_table) {
		spin_unlock_irqrestore(&ptscan_lock, flags);
		return;
	}
	counter = rhashtable_lookup_fast(count_table, &pfn, params);
	if (!counter) {
		spin_unlock_irqrestore(&ptscan_lock, flags);
		return; 
	}
	mm = counter->target_mm;
	spin_unlock_irqrestore(&ptscan_lock, flags);

	if (!mm) {
		pr_err("%s: mm is NULL!", __func__);
		return;
	}

	spin_lock_irqsave(&mm->bucket_lock, flags);
	if (!mm->bucket_sort) {
		spin_unlock_irqrestore(&mm->bucket_lock, flags);
		return;
	}
	bucket_remove_counter(mm->bucket_sort, counter);
	spin_unlock_irqrestore(&mm->bucket_lock, flags);

	kfree(counter);
}

void bucket_remove_counter(struct bucket_sort *bucket_sort, struct access_counter *counter)
{
	int bucket_idx = counter->bucket_idx;

	list_del(&counter->list);
	bucket_sort->counts[bucket_idx]--;
}

void bucket_insert_counter(struct bucket_sort *bucket_sort, struct access_counter *counter)
{
	unsigned long count = counter->count;
	int bucket_idx = get_bucket_index(count);

	counter->bucket_idx = bucket_idx;
	list_add(&counter->list, &bucket_sort->buckets[bucket_idx]);
	bucket_sort->counts[bucket_idx]++;
}

void bucket_reinsert(struct bucket_sort *bucket_sort, struct access_counter *counter)
{
	unsigned long count = counter->count;
	int bucket_idx = get_bucket_index(count);

	if (bucket_idx == counter->bucket_idx)
		return;
	else {
		bucket_remove_counter(bucket_sort, counter);
		bucket_insert_counter(bucket_sort, counter);
	}
}

/* 
 * count_table structure's methods
 */
static void rh_free_fn(void *ptr, void *arg)
{
	struct access_counter *counter = ptr;
	destroy_access_counter(counter);
}

/*
 * PT scan with vaddr
 */

static int ptscan_pte_entry(pte_t *pte, unsigned long addr, unsigned long next,
					struct mm_walk *walk)
{
	unsigned long pfn;
	struct access_counter *counter = NULL;
	struct mm_struct *mm = walk->mm;
	struct bucket_sort *bucket_sort = mm->bucket_sort;
	unsigned long flags;
	int err;

	if (!bucket_sort) {
		pr_err("There is no bucket_sort!!!");
		return 0;
	}

	if (!pte) {
		pr_err("PTE pointer is NULL!!!!!");
		return 0;
	}

	if (!pte_present(*pte))
		return 0;

	if (ptep_clear_flush_young_notify(walk->vma, addr, pte)) {
		pfn = pte_pfn(*pte);
		spin_lock_irqsave(&ptscan_lock, flags);
		counter = rhashtable_lookup_fast(count_table, &pfn, params);
		spin_unlock_irqrestore(&ptscan_lock, flags);
		if (!counter) {
			counter = new_access_counter(pfn, mm);
			if (!counter) {
				pr_err("Failed to allocate access_counter\n");
				return 0;
			}
			spin_lock_irqsave(&ptscan_lock, flags);
			err = rhashtable_insert_fast(count_table, &counter->node, params);
			spin_unlock_irqrestore(&ptscan_lock, flags);
			if (err) {
				destroy_access_counter(counter);
				pr_err("Failed to insert access_counter into count_table\n");
				return 0;
			}

			spin_lock_irqsave(&mm->bucket_lock, flags);
			bucket_insert_counter(bucket_sort, counter);
			spin_unlock_irqrestore(&mm->bucket_lock, flags);
		} else {
			inc_access_counter(counter);

			spin_lock_irqsave(&mm->bucket_lock, flags);
			bucket_reinsert(bucket_sort, counter);
			spin_unlock_irqrestore(&mm->bucket_lock, flags);
		}
	}

	return 0;
}

static const struct mm_walk_ops ptscan_ops = {
	.pte_entry = ptscan_pte_entry,
};

static void mm_ptscan(struct mm_struct *mm)
{
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma;
	unsigned long start, end, elapsed, flags;


	start = jiffies;
	for_each_vma(vmi, vma) {
		mmap_read_lock(mm);
		walk_page_vma(vma, &ptscan_ops, NULL);
		mmap_read_unlock(mm);
	}
	end = jiffies;
	elapsed = end - start;
	pr_info("pt_scan result: ");
	//pr_info("-- total accesses: %d", total_refs);
	pr_info("-- elapsed time (s): %lu/%u", elapsed, HZ);

	spin_lock_irqsave(&mm->bucket_lock, flags);
	for (int i = 0; i < NR_BUCKETS; i++) {
		pr_info("-- bucket[%d] count: %lu", i, mm->bucket_sort->counts[i]);
	}
	spin_unlock_irqrestore(&mm->bucket_lock, flags);
}

static struct mm_struct *ptscan_get_mm(int target_pid)
{
	struct pid *pid = NULL;
	struct task_struct *tsk = NULL;
	struct mm_struct *mm = NULL;

		
	pid = find_get_pid(target_pid);
	if (!pid) {
		pr_err("Failed to get pid struct\n");
		return NULL;
	}

	tsk = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!tsk) {
		pr_err("Failed to get task_struct\n");
		return NULL;
	}

	mm = tsk->mm;
	put_task_struct(tsk);

	return mm;
}

static int kptscand_fn(void *data)
{
	struct ptscan_ctx *ctx = data;
	unsigned long flags;
	struct bucket_sort *tmp_bucket_sort;
	struct rhashtable *tmp_count_table;
	
	while (!kthread_should_stop()) {
		pr_info("kptscand is running\n");

		ssleep(5);

		pr_info("target_pid: %d\n", ctx->pid);

		if (ctx->pid <= 0)
			continue;

		mm_ptscan(ctx->target_mm);
	}

	// bucket_sort 메모리 해제 및 mm_struct의 bucket_sort를 NULL로 교체.
	spin_lock_irqsave(&ctx->target_mm->bucket_lock, flags);
	tmp_bucket_sort = ctx->target_mm->bucket_sort;
	ctx->target_mm->bucket_sort = NULL;
	spin_unlock_irqrestore(&ctx->target_mm->bucket_lock, flags);

	destroy_bucket_sort(tmp_bucket_sort);

	mutex_lock(&ctx->kptscand_lock);
	ctx->kptscand = NULL;
	ctx->target_mm = NULL;
	mutex_unlock(&ctx->kptscand_lock);

	spin_lock_irqsave(&ptscan_lock, flags);
	nr_running_ctxs--;
	if (!nr_running_ctxs) {
		tmp_count_table = count_table;
		count_table = NULL;
	}
	spin_unlock_irqrestore(&ptscan_lock, flags);

	if (!count_table) {
		rhashtable_free_and_destroy(tmp_count_table, rh_free_fn, NULL);
		kfree(tmp_count_table);
	}

	pr_info("kptscand has stopped\n");
	return 0;
}
/*
 * PT scan with vaddr End.
 */

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
#include <linux/rhashtable.h>
#include <linux/list.h>
#include <linux/pagewalk.h>
#include <linux/mmu_notifier.h>

#include "../internal.h"
#include "ptscan.h"

static DEFINE_MUTEX(ptscan_lock);
static int nr_running_ctxs;

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

int ptscan_start(struct ptscan_ctx *ctx)
{
	int err = -EBUSY;

	mutex_lock(&ptscan_lock);
	mutex_lock(&ctx->kptscand_lock);
	if (!ctx->kptscand) {
		err = 0;
		ctx->kptscand = kthread_run(kptscand_fn, ctx, "kptscand.%d",
				nr_running_ctxs);
		if (IS_ERR(ctx->kptscand)) {
			err = PTR_ERR(ctx->kptscand);
			ctx->kptscand = NULL;
		}
	}
	nr_running_ctxs++;
	mutex_unlock(&ctx->kptscand_lock);
	mutex_unlock(&ptscan_lock);

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

#define NR_BUCKETS 8
#define MAX_COUNT 8
struct access_counter {
	unsigned long pfn; // key
	unsigned long count; // value
	int bucket_idx; //bucket index
	struct rhash_head node;
	struct list_head list;
};

static struct access_counter *new_access_counter(unsigned long pfn)
{
	struct access_counter *counter = NULL;
	counter = kmalloc(sizeof(*counter), GFP_KERNEL);
	if (!counter)
		return NULL;
	counter->pfn = pfn;
	counter->count = 1;
	counter->bucket_idx = 0;
	INIT_LIST_HEAD(&counter->list);
	return counter;
}

static void destroy_access_counter(struct access_counter *counter)
{
	kfree(counter);
}

static void inc_access_counter(struct access_counter *counter)
{
	if (counter->count < MAX_COUNT)
		counter->count++;
	pr_info("count: %lu", counter->count);
}

struct bucket_sort {
	unsigned long counts[NR_BUCKETS];
	struct list_head buckets[NR_BUCKETS];
};
struct bucket_sort bucket_sort;

static int get_bucket_index(unsigned long count)
{
	int i;

	if (count > MAX_COUNT)
		count = MAX_COUNT;

	for (i = 0; i < NR_BUCKETS; i++) {
		if (count > i && count <= (i+1))
			break;
	}
	pr_info("bucket_index: %d", i);
	return i;
}

static void bucket_init(struct bucket_sort *bucket_sort)
{
	int i;
	for (i = 0; i < NR_BUCKETS; i++) {
		bucket_sort->counts[i] = 0;
		INIT_LIST_HEAD(&bucket_sort->buckets[i]);
	}
}

static void bucket_remove(struct bucket_sort *bucket_sort, struct access_counter *counter)
{
	unsigned long count = counter->count;
	int bucket_idx = counter->bucket_idx;

	list_del(&counter->list);
	bucket_sort->counts[bucket_idx]--;
}

static void bucket_insert(struct bucket_sort *bucket_sort, struct access_counter *counter)
{
	unsigned long count = counter->count;
	int bucket_idx = get_bucket_index(count);

	counter->bucket_idx = bucket_idx;
	list_add(&counter->list, &bucket_sort->buckets[bucket_idx]);
	bucket_sort->counts[bucket_idx]++;
}

static void bucket_reinsert(struct bucket_sort *bucket_sort, struct access_counter *counter)
{
	unsigned long count = counter->count;
	int bucket_idx = get_bucket_index(count);

	if (bucket_idx == counter->bucket_idx)
		return;
	else {
		bucket_remove(bucket_sort, counter);
		bucket_insert(bucket_sort, counter);
	}
}

struct rhashtable count_table;
struct rhashtable_params params = {
	.head_offset = offsetof(struct access_counter, node),
	.key_offset = offsetof(struct access_counter, pfn),
	.key_len = sizeof(unsigned long),
	.automatic_shrinking = true,
};
static void rh_free_fn(void *ptr, void *arg)
{
	kfree(ptr);
}

/*
 * PT scan with vaddr
 */

static int ptscan_pte_entry(pte_t *pte, unsigned long addr, unsigned long next,
					struct mm_walk *walk)
{
	unsigned long pfn;
	struct access_counter *counter = NULL;
	int err;

	if (!pte_present(*pte))
		return 0;

	if (ptep_clear_flush_young_notify(walk->vma, addr, pte)) {
		pfn = pte_pfn(*pte);
		counter = rhashtable_lookup_fast(&count_table, &pfn, params);
		if (!counter) {
			pr_info("pte is young, but no counter");
			counter = new_access_counter(pfn);
			if (!counter) {
				pr_err("Failed to allocate access_counter\n");
				return 0;
			}
			err = rhashtable_insert_fast(&count_table, &counter->node, params);
			if (err) {
				destroy_access_counter(counter);
				pr_err("Failed to insert access_counter into count_table\n");
				return 0;
			}
			bucket_insert(&bucket_sort, counter);
		} else {
			pr_info("pte is young, with counter");
			inc_access_counter(counter);

			bucket_reinsert(&bucket_sort, counter);
		}
	}

	return 0;
}

static const struct mm_walk_ops ptscan_ops = {
	.pte_entry = ptscan_pte_entry,
};

static void task_ptscan(struct task_struct *tsk)
{
	struct mm_struct *mm = tsk->mm;
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma;
	unsigned long start, end, elapsed;


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
	for (int i = 0; i < NR_BUCKETS; i++) {
		pr_info("-- bucket[%d] count: %lu", i, bucket_sort.counts[i]);
	}
}

static int kptscand_fn(void *data)
{
	struct ptscan_ctx *ctx = data;
	struct pid *pid = NULL;
	struct task_struct *tsk = NULL;

	// TODO: 버킷하고 count_table 초기화 코드 위치 고민하기
	// 일단 지금은 여기에서 초기화 진행
	int ret;
	bucket_init(&bucket_sort);
	ret = rhashtable_init(&count_table, &params);
	if (ret) {
		pr_err("Failed to init rhashtable\n");
		return 0;
	}

	while (!kthread_should_stop()) {
		pr_info("kptscand is running\n");

		ssleep(5);

		pr_info("target_pid: %d\n", ctx->pid);

		if (ctx->pid <= 0)
			continue;

		if (!tsk) {
			pid = find_get_pid(ctx->pid);
			if (!pid) {
				pr_err("Failed to get pid struct\n");
				break;
			}
			tsk = get_pid_task(pid, PIDTYPE_PID);
			if (!tsk) {
				pr_err("Failed to get task struct\n");
				put_pid(pid);
				break;
			}
			put_pid(pid);
		}

		task_ptscan(tsk);
	}
	if (tsk)
		put_task_struct(tsk);

	mutex_lock(&ctx->kptscand_lock);
	ctx->kptscand = NULL;
	mutex_unlock(&ctx->kptscand_lock);

	mutex_lock(&ptscan_lock);
	nr_running_ctxs--;
	mutex_unlock(&ptscan_lock);
	pr_info("kptscand has stopped\n");
	return 0;
}
/*
 * PT scan with vaddr End.
 */

/*
 * PT scan with cgroup lruvec
 */
static unsigned long isolate_lru_all_folios(struct lruvec *lruvec,
		struct list_head *dst, enum lru_list lru)
{
	struct list_head *src = &lruvec->lists[lru];
	unsigned long nr_taken = 0;
	unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
	unsigned long nr_pages;
	struct folio *first_folio = NULL;

	while (!list_empty(src)) {
		struct list_head *move_to = src;
		struct folio *folio;
		
		folio = lru_to_folio(src);

		if (!first_folio)
			first_folio = folio;
		else if (first_folio == folio)
			break;

		nr_pages = folio_nr_pages(folio);
		if (nr_pages > 1)
			pr_info("compound page! (with %d pages)\n", nr_pages);

		if (!folio_test_lru(folio))
			goto move;

		if (unlikely(!folio_try_get(folio)))
			goto move;

		if (!folio_test_clear_lru(folio)) {
			folio_put(folio);
			goto move;
		}

		nr_taken += nr_pages;
		nr_zone_taken[folio_zonenum(folio)] += nr_pages;
		move_to = dst;
move:
		list_move(&folio->lru, move_to);
	}
	update_lru_sizes(lruvec, lru, nr_zone_taken);
	return nr_taken;
}

static void folio_list_ptscan(struct list_head *folio_list, struct mem_cgroup *memcg)
{
	struct list_head *pos;
	int total_refs = 0;
	unsigned long start, end, elapsed;

	start = jiffies;
	list_for_each(pos, folio_list) {
		struct folio *folio = list_entry(pos, struct folio, lru);
		int referenced_ptes = 0;
		unsigned long vm_flags;
		// TODO: multiple page도 고려.
		struct page *page = folio_page(folio, 0);
		unsigned long pfn = page_to_pfn(page);
		struct access_counter *counter = NULL;
		int err;

		referenced_ptes = folio_referenced(folio, 0, memcg, &vm_flags);
		total_refs += referenced_ptes;

		counter = rhashtable_lookup_fast(&count_table, &pfn, params);

		if (!counter) {
			counter = new_access_counter(pfn);
			if (!counter) {
				pr_err("Failed to allocate access_counter\n");
				continue;
			}
			err = rhashtable_insert_fast(&count_table, &counter->node, params);
			if (err) {
				destroy_access_counter(counter);
				pr_err("Failed to insert access_counter into count_table\n");
				continue;
			}

			bucket_insert(&bucket_sort, counter);
		} else {
			inc_access_counter(counter);

			bucket_reinsert(&bucket_sort, counter);
		}
	}
	end = jiffies;
	elapsed = end - start;
	pr_info("pt_scan result: ");
	pr_info("-- total accesses: %d", total_refs);
	pr_info("-- elapsed time (s): %lu/%u", elapsed, HZ);
	for (int i = 0; i < NR_BUCKETS; i++) {
		pr_info("-- bucket[%d] count: %lu", i, bucket_sort.counts[i]);
	}
}

static void lruvec_ptscan(struct lruvec *lruvec, struct mem_cgroup *memcg)
{
	enum lru_list lru;
	unsigned long nr_taken, nr_moved;
	unsigned long start, end, elapsed;

	for_each_evictable_lru(lru) {
		LIST_HEAD(folio_list);

		lru_add_drain();

		start = jiffies;
		spin_lock_irq(&lruvec->lru_lock);
		nr_taken = isolate_lru_all_folios(lruvec, &folio_list, lru);
		spin_unlock_irq(&lruvec->lru_lock);
		end = jiffies;
		elapsed = end - start;
		pr_info("isolate_lru_all_folios elapsed time: %lu/%u", elapsed, HZ);

		folio_list_ptscan(&folio_list, memcg);

		spin_lock_irq(&lruvec->lru_lock);
		nr_moved = move_folios_to_lru(lruvec, &folio_list);
		spin_unlock_irq(&lruvec->lru_lock);

		mem_cgroup_uncharge_list(&folio_list);
		free_unref_page_list(&folio_list);
		if (nr_taken != nr_moved)
			pr_info("%s: nr_taken != nr_moved\n", __func__);
	}
}

static void memcg_ptscan(struct mem_cgroup *memcg)
{
	struct mem_cgroup_per_node *mz;
	struct lruvec *lruvec;

	if (!memcg) {
		pr_err("%s: memcg is NULL\n", __func__); 
		return;
	}

	mz = memcg->nodeinfo[0];
	lruvec = &mz->lruvec;

	lruvec_ptscan(lruvec, memcg);
}

static int kptscand_fn_cgroup(void *data)
{
	struct ptscan_ctx *ctx = data;
	struct pid *pid = NULL;
	struct task_struct *tsk = NULL;
	struct mem_cgroup *memcg = NULL;

	// TODO: 버킷하고 count_table 초기화 코드 위치 고민하기
	// 일단 지금은 여기에서 초기화 진행
	int ret;
	bucket_init(&bucket_sort);
	ret = rhashtable_init(&count_table, &params);
	if (ret) {
		pr_err("Failed to init rhashtable\n");
		return 0;
	}

	while (!kthread_should_stop()) {
		pr_info("kptscand is running\n");

		ssleep(5);

		pr_info("target_pid: %d\n", ctx->pid);

		if (ctx->pid <= 0)
			continue;

		if (!memcg) {
			pid = find_get_pid(ctx->pid);
			if (!pid) {
				pr_err("Failed to get pid struct\n");
				break;
			}

			tsk = get_pid_task(pid, PIDTYPE_PID);
			if (!tsk) {
				pr_err("Failed to get task struct\n");
				put_pid(pid);
				break;
			}

			rcu_read_lock();
			memcg = mem_cgroup_from_task(tsk);
			if (!memcg) {
				rcu_read_unlock();
				pr_err("Failed to get mem_cgroup\n");
				put_task_struct(tsk);
				put_pid(pid);
				break;
			}
			rcu_read_unlock();
			put_task_struct(tsk);
			put_pid(pid);
		}
		memcg_ptscan(memcg);
	}

	pr_info("kptscand has stopped\n");
	return 0;
}
/*
 * PT scan with cgroup lruvec End.
 */

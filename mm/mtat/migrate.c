// SPDX-License-Identifier: GPL-2.0
/*
 * Migration Daemon
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#define pr_fmt(fmt) "migrate: " fmt

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
#include <linux/migrate.h>
#include <linux/mtat.h>

#include "../internal.h"

static int kmigrated_fn(void *data);

struct migrate_ctx *migrate_new_ctx(void)
{
	struct migrate_ctx *ctx;
	int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	mutex_init(&ctx->kmigrated_lock);

	ctx->lc_pids = kmalloc(sizeof(int) * MAX_NUM_LC, GFP_KERNEL);
	if (!ctx->lc_pids) {
		pr_err("failed to allocate lc_pids\n");
		kfree(ctx);
		return NULL;
	}

	ctx->be_pids = kmalloc(sizeof(int) * MAX_NUM_BE, GFP_KERNEL);
	if (!ctx->be_pids) {
		pr_err("failed to allocate be_pids\n");
		kfree(ctx->lc_pids);
		kfree(ctx);
		return NULL;
	}

	ctx->lc_wss = kmalloc(sizeof(unsigned long) * MAX_NUM_LC, GFP_KERNEL);
	if (!ctx->lc_wss) {
		pr_err("failed to allocate lc_wss\n");
		kfree(ctx->lc_pids);
		kfree(ctx->be_pids);
		kfree(ctx);
		return NULL;
	}

	for (i = 0; i < MAX_NUM_LC; i++) {
		ctx->lc_pids[i] = -1;
		ctx->lc_wss[i] = 0;
	}
	for (i = 0; i < MAX_NUM_BE; i++)
		ctx->be_pids[i] = -1;

	return ctx;
}

void migrate_destroy_ctx(struct migrate_ctx *ctx)
{
	kfree(ctx->lc_pids);
	kfree(ctx->be_pids);
	kfree(ctx);
}

int migrate_start(struct migrate_ctx *ctx)
{
	int err = -EBUSY;
	
	mutex_lock(&ctx->kmigrated_lock);
	if (!ctx->kmigrated) {
		err = 0;
		ctx->kmigrated = kthread_run(kmigrated_fn, ctx, "kmigrated");
		if (IS_ERR(ctx->kmigrated)) {
			err = PTR_ERR(ctx->kmigrated);
			ctx->kmigrated = NULL;
		}
	}
	mutex_unlock(&ctx->kmigrated_lock);

	return err;
}

int migrate_stop(struct migrate_ctx *ctx)
{
	struct task_struct *tsk;
	
	mutex_lock(&ctx->kmigrated_lock);
	tsk = ctx->kmigrated;
	if (tsk) {
		get_task_struct(tsk);
		mutex_unlock(&ctx->kmigrated_lock);
		kthread_stop(tsk);
		put_task_struct(tsk);
		return 0;
	}
	mutex_unlock(&ctx->kmigrated_lock);

	return -EPERM;
}

static unsigned int migrate_folio_list(struct list_head *folio_list, int nid)
{
	unsigned int nr_migrated_pages = 0;
	struct folio *folio;
	struct migration_target_control mtc = {
		.nid = nid,
		.gfp_mask = (GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) | __GFP_NOWARN |
			__GFP_NOMEMALLOC | GFP_NOWAIT
	};

	pr_info("%s called\n", __func__);

	if (list_empty(folio_list)) {
		pr_info("%s: folio list is empty\n", __func__);
		return 0;
	}

	if (migrate_pages(folio_list, alloc_migration_target,
				NULL, (unsigned long)&mtc, MIGRATE_ASYNC,
				MR_NUMA_MISPLACED, &nr_migrated_pages)) {
		pr_err("migration partially failed.\n");
	}

	while (!list_empty(folio_list)) {
		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}

	return nr_migrated_pages;
}

static void scan_bucket_sort_list(struct bucket_sort *bsort,
		struct list_head *bsort_head, struct list_head *folios,
		unsigned int *nr, unsigned int target_nr)
{
	struct folio *folio = NULL;
	struct access_counter *counter = NULL;

	while(!list_empty(bsort_head)) {
		if (*nr >= target_nr)
			break;
		counter = list_first_entry(bsort_head, typeof(*counter), list);
		folio = page_folio(pfn_to_page(counter->pfn));
		
		bucket_remove_counter(bsort, counter);
		destroy_access_counter(counter);

		if (!folio_mapcount(folio))
			continue;
		if (!folio_isolate_lru(folio))
			continue;
		list_add_tail(&folio->lru, folios);
		*nr += folio_nr_pages(folio);
	}
}

// lc migration 수행
// - PMEM bucket scan
//  - hot set에 해당되는 page가 존재하는 지 확인
//	- hot set이 있다면 DRAM bucket scan
//	 - hot set이 아닌 page를 찾으면 migration 수행
//	 - lc의 victim page가 부족한 경우, 
//	   be의 DRAM bucket scan 수행
//	  - hot set 상관없이 idx 낮은 순으로 migration 수행
// migrate한 데이터 크기를 바이트 단위로 반환
static unsigned int do_lc_migration(int lc_pid, int be_pid, unsigned long wss)
{
	LIST_HEAD(promote_folios);
	LIST_HEAD(demote_folios);
	struct mm_struct *lc_mm, *be_mm;
	int i;
	unsigned int nr_promote, nr_demote, max_promote, max_demote;
	struct bucket_sort *bsort;
	unsigned long phs, dhs, dcs, ds, hs;

	pr_info("%s called\n", __func__);

	lc_mm = ptscan_get_mm(lc_pid);
	be_mm = ptscan_get_mm(be_pid);

	spin_lock(&lc_mm->bucket_lock);
	if (!lc_mm->bucket_sort_arr) {
		spin_unlock(&lc_mm->bucket_lock);
		pr_err("%s: lc bucket_sort is NULL\n", __func__);
		return 0;
	}
	phs = bucket_hot_size(lc_mm->bucket_sort_arr[1]);
	dhs = bucket_hot_size(lc_mm->bucket_sort_arr[0]);
	dcs = bucket_cold_size(lc_mm->bucket_sort_arr[0]);
	spin_unlock(&lc_mm->bucket_lock);

	ds = dhs + dcs;
	hs = phs + dhs;
	wss /= PAGE_SIZE;

	spin_lock(&be_mm->bucket_lock);
	if (!be_mm->bucket_sort_arr) {
		spin_unlock(&be_mm->bucket_lock);
		pr_err("%s: be bucket_sort is NULL\n", __func__);
		return 0;
	}
	spin_unlock(&be_mm->bucket_lock);

	nr_promote = 0;
	nr_demote = 0;
	max_promote = 2621440; // 10G

// hot promotion
	spin_lock(&lc_mm->bucket_lock);
	// lc PMEM bucket scan
	bsort = lc_mm->bucket_sort_arr[1];
	for (i = NR_BUCKETS-1; i >= hot_threshold-1; i--) {
		if (!bsort->counts[i])
			continue;
		scan_bucket_sort_list(bsort, &bsort->buckets[i],
				&promote_folios, &nr_promote, max_promote);

		if (nr_promote >= max_promote)
			break;
	}
	spin_unlock(&lc_mm->bucket_lock);

	if (nr_promote >= max_promote)
		goto warm_demotion;

// warm promotion
    if (dcs >= wss)
		goto be_promotion;

	max_promote = min(max_promote, (unsigned int) (nr_promote + wss - dcs));

	spin_lock(&lc_mm->bucket_lock);
	bsort = lc_mm->bucket_sort_arr[1];
	for (i = hot_threshold-2; i >= 0; i--) {
		if (!bsort->counts[i])
			continue;
		scan_bucket_sort_list(bsort, &bsort->buckets[i],
				&promote_folios, &nr_promote, max_promote);
		if (nr_promote >= max_promote)
			break;
	}
	spin_unlock(&lc_mm->bucket_lock);

be_promotion:
	if (ds <= hs + wss)
		goto warm_demotion;

	max_promote = nr_promote + ds - hs - wss;

	spin_lock(&be_mm->bucket_lock);
	bsort = be_mm->bucket_sort_arr[1];
	for (i = NR_BUCKETS-1; i >= 0; i--) {
		if (!bsort->counts[i])
			continue;
		scan_bucket_sort_list(bsort, &bsort->buckets[i],
				&promote_folios, &nr_promote, max_promote);

		if (nr_promote >= max_promote)
			break;
	}
	spin_unlock(&be_mm->bucket_lock);

warm_demotion:
	if (dcs <= wss)
		goto be_demotion;

	max_demote = min(nr_promote, (unsigned int)(dcs - wss));

	spin_lock(&lc_mm->bucket_lock);
	bsort = lc_mm->bucket_sort_arr[0];
	for (i = 0; i < hot_threshold-1; i++) {
		if (!bsort->counts[i])
			continue;
		scan_bucket_sort_list(bsort, &bsort->buckets[i],
				&demote_folios, &nr_demote, max_demote);

		if (nr_demote >= max_demote)
			break;
	}
	spin_unlock(&lc_mm->bucket_lock);

be_demotion:
	spin_lock(&be_mm->bucket_lock);
	bsort = be_mm->bucket_sort_arr[0];
	for (i = 0; i < NR_BUCKETS; i++) {
		if (!bsort->counts[i])
			continue;
		scan_bucket_sort_list(bsort, &bsort->buckets[i],
				&demote_folios, &nr_demote, nr_promote);

		if (nr_demote >= nr_promote)
			break;
	}
	spin_unlock(&be_mm->bucket_lock);

//do_migration
	nr_demote = migrate_folio_list(&demote_folios, 1);
	nr_promote = migrate_folio_list(&promote_folios, 0);

	return nr_demote + nr_promote;
}

// be migration 수행
// - PMEM bucket scan
//  - hot set 검출
//  - DRAM bucket scan
//   - hot set이 아닌 page와 migration 수행
//   - victim page가 부족하면 그대로 종료
// migrate한 데이터 크기를 바이트 단위로 반환
static unsigned int do_be_migration(int be_pid)
{
	LIST_HEAD(promote_folios);
	LIST_HEAD(demote_folios);
	struct mm_struct *mm;
	int i;
	unsigned int max_demote, nr_promote, nr_demote;
	struct bucket_sort *bsort;
	unsigned long start, end, elapsed;

	pr_info("%s called\n", __func__);

	mm = ptscan_get_mm(be_pid);
	nr_promote = 0;
	nr_demote = 0;
	max_demote = 0;

	start = jiffies;
	spin_lock(&mm->bucket_lock);
	if (!mm->bucket_sort_arr) {
		spin_unlock(&mm->bucket_lock);
		pr_err("%s: be bucket_sort is NULL\n", __func__);
		return 0;
	}

	bsort = mm->bucket_sort_arr[0];
	max_demote = (unsigned int) bucket_cold_size(bsort);

	// PMEM bucket scan
	bsort = mm->bucket_sort_arr[1];
	for (i = NR_BUCKETS-1; i >= hot_threshold-1; i--) {
		if (!bsort->counts[i])
			continue;
		scan_bucket_sort_list(bsort, &bsort->buckets[i],
				&promote_folios, &nr_promote, max_demote);

		if (nr_promote >= max_demote)
			break;
	}

	if (!nr_promote)
		goto do_migration;

	// DRAM bucket scan
	bsort = mm->bucket_sort_arr[0];
	for (i = 0; i < hot_threshold-1; i++) {
		if (!bsort->counts[i])
			continue;
		scan_bucket_sort_list(bsort, &bsort->buckets[i],
				&demote_folios, &nr_demote, nr_promote);

		if (nr_demote >= nr_promote)
			break;
	}

do_migration:
	spin_unlock(&mm->bucket_lock);
	end = jiffies;
	elapsed = end - start;
	pr_info("kmigrated: bucket scan time - %lu/%u\n", elapsed, HZ);

	pr_info("expected demotion size: %u MB\n", nr_demote * 4 / 1024);
	pr_info("expected promotion size: %u MB\n", nr_promote * 4 / 1024);
	start = jiffies;
	nr_demote = migrate_folio_list(&demote_folios, 1); // demote to node 1 (PMEM)
	nr_promote = migrate_folio_list(&promote_folios, 0); // promote to node 0 (DRAM)
	end = jiffies;
	elapsed = end - start;
	pr_info("kmigrated: migration time - %lu/%u\n", elapsed, HZ);

	pr_info("real demotion size: %u MB\n", nr_demote * 4 / 1024);
	pr_info("real promotion size: %u MB\n", nr_promote * 4 / 1024);

	return nr_demote + nr_promote;
}

/*
 * 각 pid에 대해서 migration 수행함.
 * 우선 lc+be 하나씩만 있는 경우를 가정하고 구현 진행.
 */
static void do_migration(struct migrate_ctx *ctx)
{
	int *lc_pids = ctx->lc_pids;
	int *be_pids = ctx->be_pids;
	unsigned int lc_migrated_sz = 0;
	unsigned int be_migrated_sz = 0;
	
	if (lc_pids[0] != -1 && be_pids[0] != -1) 
		lc_migrated_sz = do_lc_migration(lc_pids[0], be_pids[0], ctx->lc_wss[0]);
	if (be_pids[0] != -1) 
		be_migrated_sz = do_be_migration(be_pids[0]);

	lc_migrated_sz = lc_migrated_sz * 4 / 1024;
	be_migrated_sz = be_migrated_sz * 4 / 1024;
	pr_info("lc migrated size: %u MB\n", lc_migrated_sz);
	pr_info("be migrated size: %u MB\n", be_migrated_sz);
	pr_info("total migrated size: %u MB\n", lc_migrated_sz + be_migrated_sz);
}

static int kmigrated_fn(void *data)
{
	struct migrate_ctx *ctx = data;
	
	while (!kthread_should_stop()) {
		pr_info("kmigrated is running\n");

		pr_info("lc_pids: %d %d %d %d\n", ctx->lc_pids[0], ctx->lc_pids[1],
											 ctx->lc_pids[2], ctx->lc_pids[3]);
		pr_info("be_pids: %d %d %d %d\n", ctx->be_pids[0], ctx->be_pids[1],
											 ctx->be_pids[2], ctx->be_pids[3]);

		ssleep(5);

		// do migration
		do_migration(ctx);
	}

	mutex_lock(&ctx->kmigrated_lock);
	ctx->kmigrated = NULL;
	mutex_unlock(&ctx->kmigrated_lock);

	pr_info("kmigrated is stopped\n");
	return 0;
}

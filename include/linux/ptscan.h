// SPDX-License-Identifier: GPL-2.0
/*
 * Page Table Scanner api
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#ifndef _PTSCAN_H_
#define _PTSCAN_H_

#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rhashtable.h>

/*
 * global setting variables
 */
extern int hot_threshold;
extern int cool_threshold;

struct access_counter;
struct bucket_sort;

struct ptscan_ctx {
	struct task_struct *kptscand;
	struct mutex kptscand_lock;
	int pid;
	struct mm_struct *target_mm;
};

struct ptscan_ctx *ptscan_new_ctx(void);
void ptscan_destroy_ctx(struct ptscan_ctx *ctx);

int ptscan_start(struct ptscan_ctx *ctx);
int ptscan_stop(struct ptscan_ctx *ctx);

#define NR_BUCKETS 20
#define MAX_ACCESS_COUNTER_VALUE 20 // 이 값도 포함 MAX
struct access_counter { 
	unsigned long pfn; // key
	unsigned long count; // value
	int bucket_idx;
	int cool_clock;
	struct mm_struct *target_mm;
	struct rhash_head node;
	struct list_head list;
};
struct bucket_sort {
	unsigned long counts[NR_BUCKETS];
	struct list_head buckets[NR_BUCKETS];
	int cool_clock;
};
void bucket_init(struct bucket_sort *bucket_sort);
void bucket_remove_page(struct page *page);
void bucket_remove_counter(struct bucket_sort *bucket_sort, struct access_counter *counter);
void bucket_insert_counter(struct bucket_sort *bucket_sort, struct access_counter *counter);
void bucket_reinsert(struct bucket_sort *bucket_sort, struct access_counter *counter);

#endif /* _PTSCAN_H_ */

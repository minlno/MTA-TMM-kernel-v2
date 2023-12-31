// SPDX-License-Identifier: GPL-2.0
/*
 * Page Table Scanner api
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#ifndef _MTAT_H_
#define _MTAT_H_

#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rhashtable.h>

/*
 * global setting variables
 */
extern int hot_threshold;
extern int cool_threshold;

/*
 * PEBS
 */

struct pebs_ctx {
	struct mutex pebs_lock;
	bool running;
	int nr;
	int *pids;
	struct mm_struct **mms;
};
struct pebs_ctx *pebs_new_ctx(int nr_pids);
void pebs_destroy_ctx(struct pebs_ctx *ctx);

int pebs_start(struct pebs_ctx *ctx);
int pebs_stop(struct pebs_ctx *ctx);


/*
 * PTSCAN
 */
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

struct mm_struct *ptscan_get_mm(int target_pid);

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
};

void inc_access_counter(struct access_counter *counter);
struct access_counter *new_access_counter(unsigned long pfn, struct mm_struct *mm);
void destroy_access_counter(struct access_counter *counter);
struct bucket_sort **alloc_bucket_sort_array(void);
void destroy_bucket_sort_array(struct bucket_sort **bucket_sort_arr);
void bucket_init_array(struct bucket_sort **bucket_sort_arr);
void bucket_remove_page(struct page *page);
void bucket_remove_counter(struct bucket_sort *bucket_sort, struct access_counter *counter);
void bucket_insert_counter(struct bucket_sort *bucket_sort, struct access_counter *counter);
void bucket_reinsert(struct bucket_sort *bucket_sort, struct access_counter *counter);
unsigned long bucket_hot_size(struct bucket_sort *bucket_sort);
unsigned long bucket_cold_size(struct bucket_sort *bucket_sort);
void print_bucket_sort_array(struct bucket_sort **bucket_sort_arr);

/*
 * MIGRATE
 */

#define MAX_NUM_LC 4
#define MAX_NUM_BE 4
struct migrate_ctx {
	struct task_struct *kmigrated;
	struct mutex kmigrated_lock;
	// 최대 4개의 pid씩 존재 가능
	// 초기값은 -1이고 앞에서부터 값이 대입됨. (lc[0] = pid, lc[1] = -1, ...)
	int *lc_pids;
	int *be_pids;
	unsigned long *lc_wss; // Byte 단위
};

struct migrate_ctx *migrate_new_ctx(void);
void migrate_destroy_ctx(struct migrate_ctx *ctx);

int migrate_start(struct migrate_ctx *ctx);
int migrate_stop(struct migrate_ctx *ctx);



#endif /* _MTAT_H_ */

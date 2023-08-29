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
#include <linux/mtat.h>

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
		kfree(ctx);
		return NULL;
	}

	ctx->be_pids = kmalloc(sizeof(int) * MAX_NUM_BE, GFP_KERNEL);
	if (!ctx->be_pids) {
		kfree(ctx->lc_pids);
		kfree(ctx);
		return NULL;
	}

	for (i = 0; i < MAX_NUM_LC; i++)
		ctx->lc_pids[i] = -1;
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

static int kmigrated_fn(void *data)
{
	struct migrate_ctx *ctx = data;
	int i;
	
	while (!kthread_should_stop()) {
		pr_info("kmigrated is running\n");

		for (i = 0; i < MAX_NUM_LC; i++)
			pr_info("lc_pids[%d]: %d\n", i, ctx->lc_pids[i]);
		for (i = 0; i < MAX_NUM_BE; i++)
			pr_info("be_pids[%d]: %d\n", i, ctx->be_pids[i]);

		ssleep(5);
	}

	mutex_lock(&ctx->kmigrated_lock);
	ctx->kmigrated = NULL;
	mutex_unlock(&ctx->kmigrated_lock);

	pr_info("kmigrated is stopped\n");
	return 0;
}

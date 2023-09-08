// SPDX-License-Identifier: GPL-2.0
/*
 * MTAT sysfs Interface
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/mtat.h>

#include "sysfs-common.h"

/*
 * global setting variables
 */
// lock은 잡지 않음
// 아래 변수를 수정할 때에는, 미리 kptscand, kmigrated를 멈춰야함.
int hot_threshold = 8;
int cool_threshold = 16;

/*
 * setting directory
 */

struct mtat_sysfs_setting {
	struct kobject kobj;
};

static struct mtat_sysfs_setting *mtat_sysfs_setting_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_setting), GFP_KERNEL);
}

static ssize_t hot_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	return sysfs_emit(buf, "%d\n", hot_threshold);
}

static ssize_t hot_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int hot, err;
	
	err = kstrtoint(buf, 0, &hot);
	if (err)
		return err;
	if (hot < 0)
		return -EINVAL;

	hot_threshold = hot;

	return count;
}

static ssize_t cool_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	return sysfs_emit(buf, "%d\n", cool_threshold);
}

static ssize_t cool_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int cool, err;
	
	err = kstrtoint(buf, 0, &cool);
	if (err)
		return err;
	if (cool < 0)
		return -EINVAL;

	cool_threshold = cool;

	return count;
}

static void mtat_sysfs_setting_release(struct kobject *kobj)
{
	struct mtat_sysfs_setting *setting = container_of(kobj,
			struct mtat_sysfs_setting, kobj);

	kfree(setting);
}

static struct kobj_attribute mtat_sysfs_setting_hot_attr =
		__ATTR_RW_MODE(hot, 0600);

static struct kobj_attribute mtat_sysfs_setting_cool_attr =
		__ATTR_RW_MODE(cool, 0600);

static struct attribute *mtat_sysfs_setting_attrs[] = {
	&mtat_sysfs_setting_hot_attr.attr,
	&mtat_sysfs_setting_cool_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_setting);

static const struct kobj_type mtat_sysfs_setting_ktype = {
	.release = mtat_sysfs_setting_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_setting_groups,
};

/*
 * pid directory (for kmigrated)
 */

struct mtat_sysfs_kmigrated_pid {
	struct kobject kobj;
	int pid;
	int is_lc;
	unsigned long wss; // warm set size (Bytes)
};

static struct mtat_sysfs_kmigrated_pid *mtat_sysfs_kmigrated_pid_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_kmigrated_pid), GFP_KERNEL);
}

static ssize_t migrate_pid_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct mtat_sysfs_kmigrated_pid *kmigrated_pid = container_of(kobj,
			struct mtat_sysfs_kmigrated_pid, kobj);

	return sysfs_emit(buf, "%d\n", kmigrated_pid->pid);
}

static ssize_t migrate_pid_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct mtat_sysfs_kmigrated_pid *kmigrated_pid;
	int pid, err;

	err = kstrtoint(buf, 0, &pid);
	if (err)
		return err;
	if (pid < 0)
		return -EINVAL;

	kmigrated_pid = container_of(kobj, struct mtat_sysfs_kmigrated_pid, kobj);
	kmigrated_pid->pid = pid;

	return count;
}

static ssize_t lc_mode_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct mtat_sysfs_kmigrated_pid *kmigrated_pid = container_of(kobj,
			struct mtat_sysfs_kmigrated_pid, kobj);

	return sysfs_emit(buf, "%d\n", kmigrated_pid->is_lc);
}

static ssize_t lc_mode_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct mtat_sysfs_kmigrated_pid *kmigrated_pid;
	int lc_mode, err;

	err = kstrtoint(buf, 0, &lc_mode);
	if (err)
		return err;
	if (lc_mode != 0 && lc_mode != 1)
		return -EINVAL;

	kmigrated_pid = container_of(kobj, struct mtat_sysfs_kmigrated_pid, kobj);
	kmigrated_pid->is_lc = lc_mode;

	return count;
}

static ssize_t warm_size_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct mtat_sysfs_kmigrated_pid *kmigrated_pid = container_of(kobj,
			struct mtat_sysfs_kmigrated_pid, kobj);

	return sysfs_emit(buf, "%lu\n", kmigrated_pid->wss);
}

static ssize_t warm_size_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct mtat_sysfs_kmigrated_pid *kmigrated_pid;
	char *end;
	unsigned long wss;

	wss = memparse(buf, &end);
	if (*end != '\0')
		return -EINVAL;

	kmigrated_pid = container_of(kobj, struct mtat_sysfs_kmigrated_pid, kobj);
	kmigrated_pid->wss = wss;

	return count;
}

static void mtat_sysfs_kmigrated_pid_release(struct kobject *kobj)
{
	kfree(container_of(kobj, struct mtat_sysfs_kmigrated_pid, kobj));
}

static struct kobj_attribute mtat_sysfs_kmigrated_pid_migrate_pid_attr =
		__ATTR_RW_MODE(migrate_pid, 0600);

static struct kobj_attribute mtat_sysfs_kmigrated_pid_lc_mode_attr =
		__ATTR_RW_MODE(lc_mode, 0600);

static struct attribute *mtat_sysfs_kmigrated_pid_attrs[] = {
	&mtat_sysfs_kmigrated_pid_migrate_pid_attr.attr,
	&mtat_sysfs_kmigrated_pid_lc_mode_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_kmigrated_pid);

static const struct kobj_type mtat_sysfs_kmigrated_pid_ktype = {
	.release = mtat_sysfs_kmigrated_pid_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_kmigrated_pid_groups,
};


/*
 * enum mtat_sysfs_cmd - Commands for a specific kptscand/kmigrated.
 */
enum mtat_sysfs_cmd {
	/* @MTAT_SYSFS_CMD_ON: Turn the kptscand/kmigrated on. */
	MTAT_SYSFS_CMD_ON,
	/* @MTAT_SYSFS_CMD_OFF: Turn the kptscand/kmigrated off. */
	MTAT_SYSFS_CMD_OFF,
	/* @NR_MTAT_SYSFS_CMDS: Total number of MTAT sysfs commands. */
	NR_MTAT_SYSFS_CMDS,
};

/* Should match with enum mtat_sysfs_cmd */
static const char * const mtat_sysfs_cmd_strs[] = {
	"on",
	"off",
};

/*
 * kmigrated directory
 */

struct mtat_sysfs_kmigrated {
	struct kobject kobj;
	struct migrate_ctx *migrate_ctx;
	struct mtat_sysfs_kmigrated_pid **pids;
	int nr;
};

static struct mtat_sysfs_kmigrated *mtat_sysfs_kmigrated_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_kmigrated), GFP_KERNEL);
}

static void mtat_sysfs_kmigrated_rm_dirs(struct mtat_sysfs_kmigrated *kmigrated)
{
	struct mtat_sysfs_kmigrated_pid **pids = kmigrated->pids;
	int i;
	for (i = 0; i < kmigrated->nr; i++) {
		kobject_put(&pids[i]->kobj);
	}
	kmigrated->nr = 0;
	kfree(pids);
	kmigrated->pids = NULL;
}

static int mtat_sysfs_kmigrated_add_dirs(struct mtat_sysfs_kmigrated *kmigrated,
		int nr_pids)
{
	struct mtat_sysfs_kmigrated_pid **pids, *kmigrated_pid;
	int err, i;

	mtat_sysfs_kmigrated_rm_dirs(kmigrated);
	if (!nr_pids)
		return 0;

	pids = kmalloc_array(nr_pids, sizeof(*pids), GFP_KERNEL | __GFP_NOWARN);
	if (!pids)
		return -ENOMEM;
	kmigrated->pids = pids;

	for (i = 0; i < nr_pids; i++) {
		kmigrated_pid = mtat_sysfs_kmigrated_pid_alloc();
		if (!kmigrated_pid) {
			mtat_sysfs_kmigrated_rm_dirs(kmigrated);
			return -ENOMEM;
		}
		
		err = kobject_init_and_add(&kmigrated_pid->kobj,
				&mtat_sysfs_kmigrated_pid_ktype, &kmigrated->kobj,
				"%d", i);
		if (err)
			goto out;

		pids[i] = kmigrated_pid;
		kmigrated->nr++;
	}
	return 0;

out:
	mtat_sysfs_kmigrated_rm_dirs(kmigrated);
	kobject_put(&kmigrated_pid->kobj);
	return err;
}

static bool mtat_sysfs_migrate_ctx_running(struct migrate_ctx *ctx)
{
	bool running;

	mutex_lock(&ctx->kmigrated_lock);
	running = ctx->kmigrated != NULL;
	mutex_unlock(&ctx->kmigrated_lock);
	return running;
}

static inline bool mtat_sysfs_kmigrated_running(struct mtat_sysfs_kmigrated *kmigrated)
{
	return kmigrated->migrate_ctx &&
		mtat_sysfs_migrate_ctx_running(kmigrated->migrate_ctx);
}

static int mtat_sysfs_turn_migrate_on(struct mtat_sysfs_kmigrated *kmigrated)
{
	struct migrate_ctx *ctx;
	struct mtat_sysfs_kmigrated_pid **pids = kmigrated->pids;
	int err, i, lc_idx, be_idx;

	if (mtat_sysfs_kmigrated_running(kmigrated))
		return -EBUSY;

	if (kmigrated->migrate_ctx)
		migrate_destroy_ctx(kmigrated->migrate_ctx);
	kmigrated->migrate_ctx = NULL;

	ctx = migrate_new_ctx();

	lc_idx = 0;
	be_idx = 0;
	for (i = 0; i < kmigrated->nr; i++) {
		if (pids[i]->is_lc) {
			BUG_ON(lc_idx >= MAX_NUM_LC);
			ctx->lc_pids[lc_idx] = pids[i]->pid;
			lc_idx++;
		} else {
			BUG_ON(be_idx >= MAX_NUM_LC);
			ctx->be_pids[be_idx] = pids[i]->pid;
			be_idx++;
		}
	}

	err = migrate_start(ctx);
	if (err) {
		migrate_destroy_ctx(ctx);
		return err;
	}
	kmigrated->migrate_ctx = ctx;
	return err;
}

static int mtat_sysfs_turn_migrate_off(struct mtat_sysfs_kmigrated *kmigrated)
{
	if (!kmigrated->migrate_ctx)
		return -EINVAL;
	return migrate_stop(kmigrated->migrate_ctx);
}

static int mtat_sysfs_kmigrated_handle_cmd(enum mtat_sysfs_cmd cmd,
		struct mtat_sysfs_kmigrated *kmigrated)
{
	switch (cmd) {
	case MTAT_SYSFS_CMD_ON:
		return mtat_sysfs_turn_migrate_on(kmigrated);
	case MTAT_SYSFS_CMD_OFF:
		return mtat_sysfs_turn_migrate_off(kmigrated);
	default:
		break;
	}

	return 0;
}

static ssize_t migrate_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct mtat_sysfs_kmigrated *kmigrated = container_of(kobj,
			struct mtat_sysfs_kmigrated, kobj);
	bool running = mtat_sysfs_kmigrated_running(kmigrated);

	return sysfs_emit(buf, "%s\n", running ?
			mtat_sysfs_cmd_strs[MTAT_SYSFS_CMD_ON] :
			mtat_sysfs_cmd_strs[MTAT_SYSFS_CMD_OFF]);
}

static ssize_t migrate_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct mtat_sysfs_kmigrated *kmigrated = container_of(kobj,
			struct mtat_sysfs_kmigrated, kobj);
	enum mtat_sysfs_cmd cmd;
	ssize_t ret = -EINVAL;

	if (!mutex_trylock(&mtat_sysfs_lock))
		return -EBUSY;
	for (cmd = 0; cmd < NR_MTAT_SYSFS_CMDS; cmd++) {
		if (sysfs_streq(buf, mtat_sysfs_cmd_strs[cmd])) {
			ret = mtat_sysfs_kmigrated_handle_cmd(cmd, kmigrated);
			break;
		}
	}
	mutex_unlock(&mtat_sysfs_lock);
	if (!ret)
		ret = count;
	return ret;
}

static ssize_t nr_pids_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct mtat_sysfs_kmigrated *kmigrated = container_of(kobj,
			struct mtat_sysfs_kmigrated, kobj);

	return sysfs_emit(buf, "%d\n", kmigrated->nr);
}

static ssize_t nr_pids_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct mtat_sysfs_kmigrated *kmigrated;
	int nr, err;

	err = kstrtoint(buf, 0, &nr);
	if (err)
		return err;
	if (nr < 0 || nr > 8)
		return -EINVAL;

	kmigrated = container_of(kobj, struct mtat_sysfs_kmigrated, kobj);

	if (!mutex_trylock(&mtat_sysfs_lock))
		return -EBUSY;
	err = mtat_sysfs_kmigrated_add_dirs(kmigrated, nr);
	mutex_unlock(&mtat_sysfs_lock);
	if (err)
		return err;

	return count;
}

static void mtat_sysfs_kmigrated_release(struct kobject *kobj)
{
	kfree(container_of(kobj, struct mtat_sysfs_kmigrated, kobj));
}

static struct kobj_attribute mtat_sysfs_kmigrated_migrate_attr =
		__ATTR_RW_MODE(migrate, 0600);

static struct kobj_attribute mtat_sysfs_kmigrated_nr_pids_attr =
		__ATTR_RW_MODE(nr_pids, 0600);

static struct attribute *mtat_sysfs_kmigrated_attrs[] = {
	&mtat_sysfs_kmigrated_migrate_attr.attr,
	&mtat_sysfs_kmigrated_nr_pids_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_kmigrated);

static const struct kobj_type mtat_sysfs_kmigrated_ktype = {
	.release = mtat_sysfs_kmigrated_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_kmigrated_groups,
};

/*
 * kptscand directory
 */

struct mtat_sysfs_kptscand {
	struct kobject kobj;
	struct ptscan_ctx *ptscan_ctx;
	int target_pid;
};

static struct mtat_sysfs_kptscand *mtat_sysfs_kptscand_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_kptscand), GFP_KERNEL);
}

static int mtat_sysfs_kptscand_add_dirs(struct mtat_sysfs_kptscand *kptscand)
{
	return 0;
}

static void mtat_sysfs_kptscand_rm_dirs(struct mtat_sysfs_kptscand *kptscand)
{
	;
}

static bool mtat_sysfs_ptscan_ctx_running(struct ptscan_ctx *ctx)
{
	bool running;

	mutex_lock(&ctx->kptscand_lock);
	running = ctx->kptscand != NULL;
	mutex_unlock(&ctx->kptscand_lock);
	return running;
}

static inline bool mtat_sysfs_kptscand_running(
		struct mtat_sysfs_kptscand *kptscand)
{
	return kptscand->ptscan_ctx &&
		mtat_sysfs_ptscan_ctx_running(kptscand->ptscan_ctx);
}

static int mtat_sysfs_turn_ptscan_on(struct mtat_sysfs_kptscand *kptscand)
{
	struct ptscan_ctx *ctx;
	int err;

	if (mtat_sysfs_kptscand_running(kptscand))
		return -EBUSY;

	if (kptscand->ptscan_ctx)
		ptscan_destroy_ctx(kptscand->ptscan_ctx);
	kptscand->ptscan_ctx = NULL;

	//ctx = mtat_sysfs_build_ctx(~~);
	//if (IS_ERR(ctx))
    //return PTR_ERR(ctx);
	ctx = ptscan_new_ctx();
	
	// set target pid to ctx. if target pid == 0 then return err
	ctx->pid = kptscand->target_pid;

	err = ptscan_start(ctx);
	if (err) {
		ptscan_destroy_ctx(ctx);
		return err;
	}
	kptscand->ptscan_ctx = ctx;
	return err;
}

static int mtat_sysfs_turn_ptscan_off(struct mtat_sysfs_kptscand *kptscand)
{
	if (!kptscand->ptscan_ctx)
		return -EINVAL;
	return ptscan_stop(kptscand->ptscan_ctx);
}

static int mtat_sysfs_handle_cmd(enum mtat_sysfs_cmd cmd,
		struct mtat_sysfs_kptscand *kptscand)
{
	switch (cmd) {
	case MTAT_SYSFS_CMD_ON:
		return mtat_sysfs_turn_ptscan_on(kptscand);
	case MTAT_SYSFS_CMD_OFF:
		return mtat_sysfs_turn_ptscan_off(kptscand);
	default:
		break;
	}

	return 0;
}

static ssize_t ptscan_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_kptscand *kptscand = container_of(kobj,
			struct mtat_sysfs_kptscand, kobj);
	bool running = mtat_sysfs_kptscand_running(kptscand);

	return sysfs_emit(buf, "%s\n", running ?
			mtat_sysfs_cmd_strs[MTAT_SYSFS_CMD_ON] :
			mtat_sysfs_cmd_strs[MTAT_SYSFS_CMD_OFF]);
}

static ssize_t ptscan_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct mtat_sysfs_kptscand *kptscand = container_of(kobj,
			struct mtat_sysfs_kptscand, kobj);
	enum mtat_sysfs_cmd cmd;
	ssize_t ret = -EINVAL;
	
	if (!mutex_trylock(&mtat_sysfs_lock))
		return -EBUSY;
	for (cmd = 0; cmd < NR_MTAT_SYSFS_CMDS; cmd++) {
		if (sysfs_streq(buf, mtat_sysfs_cmd_strs[cmd])) {
			ret = mtat_sysfs_handle_cmd(cmd, kptscand);
			break;
		}
	}
	mutex_unlock(&mtat_sysfs_lock);
	if (!ret)
		ret = count;
	return ret;
}

static ssize_t target_pid_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct mtat_sysfs_kptscand *kptscand = container_of(kobj,
			struct mtat_sysfs_kptscand, kobj);

	return sysfs_emit(buf, "%d\n", kptscand->target_pid);
}

static ssize_t target_pid_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct mtat_sysfs_kptscand *kptscand;
	int pid, err;

	err = kstrtoint(buf, 0, &pid);
	if (err)
		return err;
	if (pid < 0)
		return -EINVAL;

	kptscand = container_of(kobj, struct mtat_sysfs_kptscand, kobj);

	kptscand->target_pid = pid;

	return count;
}

static void mtat_sysfs_kptscand_release(struct kobject *kobj)
{
	struct mtat_sysfs_kptscand *kptscand = container_of(kobj,
			struct mtat_sysfs_kptscand, kobj);

	kfree(kptscand);
}

static struct kobj_attribute mtat_sysfs_kptscand_ptscan_attr =
		__ATTR_RW_MODE(ptscan, 0600);

static struct kobj_attribute mtat_sysfs_kptscand_target_pid_attr =
		__ATTR_RW_MODE(target_pid, 0600);

static struct attribute *mtat_sysfs_kptscand_attrs[] = {
	&mtat_sysfs_kptscand_ptscan_attr.attr,
	&mtat_sysfs_kptscand_target_pid_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_kptscand);

static const struct kobj_type mtat_sysfs_kptscand_ktype = {
	.release = mtat_sysfs_kptscand_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_kptscand_groups,
};

/*
 * kptscands directory
 */

struct mtat_sysfs_kptscands {
	struct kobject kobj;
	struct mtat_sysfs_kptscand **kptscands_arr;
	int nr;
};

static struct mtat_sysfs_kptscands *mtat_sysfs_kptscands_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_kptscands), GFP_KERNEL);
}

static void mtat_sysfs_kptscands_rm_dirs(struct mtat_sysfs_kptscands *kptscands)
{
	struct mtat_sysfs_kptscand **kptscands_arr = kptscands->kptscands_arr;
	int i;
	 
	for (i = 0; i < kptscands->nr; i++) {
		mtat_sysfs_kptscand_rm_dirs(kptscands_arr[i]);
		kobject_put(&kptscands_arr[i]->kobj);
	}
	kptscands->nr = 0;
	kfree(kptscands_arr);
	kptscands->kptscands_arr = NULL;
}

static bool mtat_sysfs_kptscands_busy(struct mtat_sysfs_kptscand **kptscands,
		int nr_kptscands)
{
	int i;

	for (i = 0; i < nr_kptscands; i++) {
		if (mtat_sysfs_kptscand_running(kptscands[i]))
			return true;
	}

	return false;
}

static int mtat_sysfs_kptscands_add_dirs(struct mtat_sysfs_kptscands *kptscands,
		int nr_kptscands)
{
	struct mtat_sysfs_kptscand **kptscands_arr, *kptscand;
	int err, i;
	
	if (mtat_sysfs_kptscands_busy(kptscands->kptscands_arr, kptscands->nr))
		return -EBUSY;

	mtat_sysfs_kptscands_rm_dirs(kptscands);
	if (!nr_kptscands)
		return 0;

	kptscands_arr = kmalloc_array(nr_kptscands, sizeof(*kptscands_arr),
			GFP_KERNEL | __GFP_NOWARN);
	if (!kptscands_arr)
		return -ENOMEM;
	kptscands->kptscands_arr = kptscands_arr;

	for (i = 0; i < nr_kptscands; i++) {
		kptscand = mtat_sysfs_kptscand_alloc();
		if (!kptscand) {
			mtat_sysfs_kptscands_rm_dirs(kptscands);
			return -ENOMEM;
		}

		err = kobject_init_and_add(&kptscand->kobj,
				&mtat_sysfs_kptscand_ktype, &kptscands->kobj,
				"%d", i);

		if (err)
			goto out;

		err = mtat_sysfs_kptscand_add_dirs(kptscand);
		if (err)
			goto out;

		kptscands_arr[i] = kptscand;
		kptscands->nr++;
	}
	return 0;

out:
	mtat_sysfs_kptscands_rm_dirs(kptscands);
	kobject_put(&kptscand->kobj);
	return err;
}

static ssize_t nr_kptscands_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct mtat_sysfs_kptscands *kptscands = container_of(kobj,
			struct mtat_sysfs_kptscands, kobj);

	return sysfs_emit(buf, "%d\n", kptscands->nr);
}

static ssize_t nr_kptscands_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct mtat_sysfs_kptscands *kptscands;
	int nr, err;

	err = kstrtoint(buf, 0, &nr);
	if (err)
		return err;
	if (nr < 0)
		return -EINVAL;

	kptscands = container_of(kobj, struct mtat_sysfs_kptscands, kobj);

	if (!mutex_trylock(&mtat_sysfs_lock))
		return -EBUSY;
	err = mtat_sysfs_kptscands_add_dirs(kptscands, nr);
	mutex_unlock(&mtat_sysfs_lock);
	if (err)
		return err;

	return count;
}

static void mtat_sysfs_kptscands_release(struct kobject *kobj)
{
	kfree(container_of(kobj, struct mtat_sysfs_kptscands, kobj));
}

static struct kobj_attribute mtat_sysfs_kptscands_nr_attr =
		__ATTR_RW_MODE(nr_kptscands, 0600);

static struct attribute *mtat_sysfs_kptscands_attrs[] = {
	&mtat_sysfs_kptscands_nr_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_kptscands);

static const struct kobj_type mtat_sysfs_kptscands_ktype = {
	.release = mtat_sysfs_kptscands_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_kptscands_groups,
};

/*
 * mtat user interface directory
 */

struct mtat_sysfs_ui_dir {
	struct kobject kobj;
	struct mtat_sysfs_kptscands *kptscands;
	struct mtat_sysfs_kmigrated *kmigrated;
	struct mtat_sysfs_setting *setting;
};

static struct mtat_sysfs_ui_dir *mtat_sysfs_ui_dir_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_ui_dir), GFP_KERNEL);
}

static int mtat_sysfs_ui_dir_add_dirs(struct mtat_sysfs_ui_dir *ui_dir)
{
	struct mtat_sysfs_kptscands *kptscands;
	struct mtat_sysfs_kmigrated *kmigrated;
	struct mtat_sysfs_setting *setting;
	int err;

	kptscands = mtat_sysfs_kptscands_alloc();
	if (!kptscands)
		return -ENOMEM;
	err = kobject_init_and_add(&kptscands->kobj,
			&mtat_sysfs_kptscands_ktype, &ui_dir->kobj,
			"kptscands");
	if (err)
		goto put_kptscands;

	kmigrated = mtat_sysfs_kmigrated_alloc();
	if (!kmigrated) {
		err = -ENOMEM;
		goto put_kptscands;
	}
	err = kobject_init_and_add(&kmigrated->kobj,
			&mtat_sysfs_kmigrated_ktype, &ui_dir->kobj,
			"kmigrated");
	if (err)
		goto put_kmigrated;

	setting = mtat_sysfs_setting_alloc();
	if (!setting) {
		err = -ENOMEM;
		goto put_kmigrated;
	}
	err = kobject_init_and_add(&setting->kobj,
			&mtat_sysfs_setting_ktype, &ui_dir->kobj,
			"setting");
	if (err)
		goto put_setting;

	ui_dir->kptscands = kptscands;
	ui_dir->kmigrated = kmigrated;
	ui_dir->setting = setting;
	
	return err;

put_setting:
	kobject_put(&setting->kobj);
put_kmigrated:
	kobject_put(&kmigrated->kobj);
put_kptscands:
	kobject_put(&kptscands->kobj);
out:
	return err;
}

static void mtat_sysfs_ui_dir_release(struct kobject *kobj)
{
	kfree(container_of(kobj, struct mtat_sysfs_ui_dir, kobj));
}

static struct attribute *mtat_sysfs_ui_dir_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_ui_dir);

static const struct kobj_type mtat_sysfs_ui_dir_ktype = {
	.release = mtat_sysfs_ui_dir_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_ui_dir_groups,
};

static int __init mtat_sysfs_init(void)
{
	struct kobject *mtat_sysfs_root;
	struct mtat_sysfs_ui_dir *admin;
	int err;

	mtat_sysfs_root = kobject_create_and_add("mtat", mm_kobj);
	if (!mtat_sysfs_root)
		return -ENOMEM;

	admin = mtat_sysfs_ui_dir_alloc();
	if (!admin) {
		kobject_put(mtat_sysfs_root);
		return -ENOMEM;
	}
	err = kobject_init_and_add(&admin->kobj, &mtat_sysfs_ui_dir_ktype,
			mtat_sysfs_root, "admin");
	if (err)
		goto out;
	err = mtat_sysfs_ui_dir_add_dirs(admin);
	if (err)
		goto out;
	return 0;

out:
	kobject_put(&admin->kobj);
	kobject_put(mtat_sysfs_root);
	return err;
}
subsys_initcall(mtat_sysfs_init);

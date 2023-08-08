// SPDX-License-Identifier: GPL-2.0
/*
 * MTAT sysfs Interface
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#include <linux/slab.h>

#include "sysfs-common.h"
#include "ptscan.h"

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

/*
 * enum mtat_sysfs_cmd - Commands for a specific kptscand.
 */
enum mtat_sysfs_cmd {
	/* @MTAT_SYSFS_CMD_ON: Turn the kptscand on. */
	MTAT_SYSFS_CMD_ON,
	/* @MTAT_SYSFS_CMD_OFF: Turn the kptscand off. */
	MTAT_SYSFS_CMD_OFF,
	/* @NR_MTAT_SYSFS_CMDS: Total number of MTAT sysfs commands. */
	NR_MTAT_SYSFS_CMDS,
};

/* Should match with enum mtat_sysfs_cmd */
static const char * const mtat_sysfs_cmd_strs[] = {
	"on",
	"off",
};

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
	
	// TODO: set target pid to ctx. if target pid == 0 then return err
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

static int mtat_sysfs_kptscands_add_dirs(struct mtat_sysfs_kptscands *kptscands,
		int nr_kptscands)
{
	struct mtat_sysfs_kptscand **kptscands_arr, *kptscand;
	int err, i;
	
	// TODO: have to check if kptscand is busy

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
};

static struct mtat_sysfs_ui_dir *mtat_sysfs_ui_dir_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_ui_dir), GFP_KERNEL);
}

static int mtat_sysfs_ui_dir_add_dirs(struct mtat_sysfs_ui_dir *ui_dir)
{
	struct mtat_sysfs_kptscands *kptscands;
	int err;

	kptscands = mtat_sysfs_kptscands_alloc();
	if (!kptscands)
		return -ENOMEM;

	err = kobject_init_and_add(&kptscands->kobj,
			&mtat_sysfs_kptscands_ktype, &ui_dir->kobj,
			"kptscands");

	if (err) {
		kobject_put(&kptscands->kobj);
		return err;
	}
	ui_dir->kptscands = kptscands;
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

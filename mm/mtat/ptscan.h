// SPDX-License-Identifier: GPL-2.0
/*
 * Page Table Scanner api
 *
 * Author: MinHo Kim <mhkim@dgist.ac.kr>
 */

#ifndef _PTSCAN_H_
#define _PTSCAN_H_

#include <linux/mutex.h>

struct ptscan_ctx {
	struct task_struct *kptscand;
	struct mutex kptscand_lock;
	int pid;
};

struct ptscan_ctx *ptscan_new_ctx(void);
void ptscan_destroy_ctx(struct ptscan_ctx *ctx);

int ptscan_start(struct ptscan_ctx *ctx);
int ptscan_stop(struct ptscan_ctx *ctx);

#endif /* _PTSCAN_H_ */

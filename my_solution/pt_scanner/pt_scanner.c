#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/cgroup.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/page_counter.h>
#include <linux/mmzone.h>
#include <linux/swap.h>
#include <linux/mm_inline.h>
#include <linux/mmdebug.h>
#include <linux/rmap.h>
#include <linux/jiffies.h>


// 어떤 cgroup을 scan할 것인지 알려주는 모듈 패러미터.
// pid를 통해 cgroup을 얻음.
static int target_pid = -1;
module_param(target_pid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

static struct task_struct *kptscand;

extern int folio_referenced(struct folio *folio, int is_locked,
				struct mem_cgroup *memcg, unsigned long *vm_flags);

// mm/vmscan.c에 존재하는 같은 이름의 함수를 거의 그대로 복사한 함수.
static void move_folios_to_lru(struct lruvec *lruvec,
		struct list_head *list, enum lru_list lru)
{
	//LIST_HEAD(folios_to_free);

	while (!list_empty(list)) {
		struct folio *folio = lru_to_folio(list);

		VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
		list_del(&folio->lru);
		/*
		if (unlikely(!folio_evictable(folio))) {
			spin_unlock_irq(&lruvec->lru_lock);
			folio_putback_lru(folio);
			spin_lock_irq(&lruvec->lru_lock);
			continue;
		}
		*/

		folio_set_lru(folio);

		/*
		if (unlikely(folio_put_testzero(folio))) {
			__folio_clear_lru_flags(folio);

			if (unlikely(folio_test_large(folio))) {
				spin_unlock_irq(&lruvec->lru_lock);
				destroy_large_folio(folio);
				spin_lock_irq(&lruvec->lru_lock);
			} else
				list_add(&folio->lru, &folios_to_free);
			
			continue;
		}
		*/

		VM_BUG_ON_FOLIO(!folio_matches_lruvec(folio, lruvec), folio);
		//lruvec_add_folio(lruvec, folio);
		list_add(&folio->lru, &lruvec->lists[lru]);
	}

	//list_splice(&folios_to_free, list);
}

/*
 * lruvec->lru_lock을 호출전에 잡아야함.
 *
 * lruvec의 lru에 해당하는 list에 포함된 모든 folio를
 * dst list에 옮김.
 *
 * mm/vmscan.c의 isolate_lru_folios() 함수를 많이 참고함.
 */
static unsigned long isolate_lru_all_folios(struct lruvec *lruvec, 
		struct list_head *dst, enum lru_list lru)
{
	struct list_head *src = &lruvec->lists[lru];
	unsigned long nr_taken = 0;
	unsigned long nr_pages;
	struct folio *first_folio = NULL;

	while (!list_empty(src)) {
		struct list_head *move_to = src;
		struct folio *folio;

		folio = lru_to_folio(src);

		// 한바퀴 다 돌았으면 while문 탈출.
		if (!first_folio)
			first_folio = folio;
		else if (first_folio == folio)
			break;

		nr_pages = folio_nr_pages(folio);

		if (!folio_test_lru(folio))
			goto move;

		if (unlikely(!folio_try_get(folio)))
			goto move;

		if (!folio_test_clear_lru(folio)) {
			folio_put(folio);
			goto move;
		}

		nr_taken += nr_pages;
		move_to = dst;
move:
		list_move(&folio->lru, move_to);
	}

	return nr_taken;
}

/*
 * folio_list에 포함된 모든 folio들의 access bit 체크.
 * 체크 후에 clean도 진행.
 */
static void folio_list_pt_scan(struct list_head *folio_list, struct mem_cgroup *memcg)
{
	struct list_head *pos;
	int total_refs = 0;
	unsigned long start, end, elapsed;

	start = jiffies;
	list_for_each(pos, folio_list) {
		struct folio *folio = list_entry(pos, struct folio, lru);
		int referenced_ptes = 0;
		unsigned long vm_flags;

		referenced_ptes = folio_referenced(folio, 0, memcg, &vm_flags);	
		total_refs += referenced_ptes;
	}
	end = jiffies;
	elapsed = end - start;
	pr_info("pt_scan result: ");
	pr_info("-- total accesses: %d", total_refs);
	pr_info("-- elapsed time (s): %lu/%u", elapsed, HZ);
}

// lruvec의 모든 list에 포함된 모든 page에 대해 pt_scan 수행.
static void lruvec_pt_scan(struct lruvec *lruvec, struct mem_cgroup *memcg)
{
	enum lru_list lru;
	unsigned long nr_taken;

	for_each_evictable_lru(lru) {
		LIST_HEAD(folio_list);

		//lru_add_drain();

		spin_lock_irq(&lruvec->lru_lock);
		nr_taken = isolate_lru_all_folios(lruvec, &folio_list, lru);	
		spin_unlock_irq(&lruvec->lru_lock);

		folio_list_pt_scan(&folio_list, memcg);

		spin_lock_irq(&lruvec->lru_lock);
		move_folios_to_lru(lruvec, &folio_list, lru);
		spin_unlock_irq(&lruvec->lru_lock);

		// 원래 다시 못되돌리면 아래의 함수를 호출해서
		// 해당 folio들을 free 해주어야 함.
		// 커널 모듈에서 아래 함수를 부를 수 없기 때문에, 
		// 일단 그냥 해제하지 않고 놔둠.
		//free_unref_page_list(&folio_list);
	}
}

// 특정 cgroup에 대해 scan 수행하는 함수
// active, inactive 리스트에 존재하는 모든 page의 
// access bit를 확인하고 clean 진행.
static void memcg_pt_scan(struct mem_cgroup *memcg)
{
	struct mem_cgroup_per_node *mz;
	struct lruvec *lruvec;

	if (!memcg) 
		return;

	mz = memcg->nodeinfo[0];
	lruvec = &mz->lruvec;

	lruvec_pt_scan(lruvec, memcg);
}

// kptscand main 함수 -> 특정 주기마다 pt scan 진행
static int kptscand_main(void *data)
{
	struct pid *pid = NULL;
	struct task_struct *task = NULL;
	struct mem_cgroup *memcg = NULL;

	while (!kthread_should_stop()) {
		pr_info("kptscand is running\n");

		ssleep(5);

		pr_info("target_pid: %d\n", target_pid);

		if (target_pid == -1) 
			continue;

		// target_pid가 -1이 아니고, memcg가 초기화되지 않은 경우,
		// 초기화 진행.
		// 초기화 실패시 while loop를 종료.
		if (!memcg) {
			pid = find_get_pid(target_pid);
			if (!pid) {
				pr_err("Failed to get pid struct\n");
				break;
			}

			task = get_pid_task(pid, PIDTYPE_PID);
			if (!task) {
				pr_err("Failed to get task struct\n");	
				put_pid(pid);
				break;
			}

			rcu_read_lock();
			memcg = mem_cgroup_from_task(task);
			if (!memcg) {
				rcu_read_unlock();
				pr_err("Failed to get mem_cgroup\n");
				put_task_struct(task);
				put_pid(pid);
				break;
			}
			rcu_read_unlock();
			put_task_struct(task);
			put_pid(pid);
		}

		pr_info("nr_pages of task %d: %lu\n", target_pid, page_counter_read(&memcg->memory));
		memcg_pt_scan(memcg);
	}

	pr_info("kptscand has stopped\n");
	return 0;
}



static int __init pt_scanner_init(void)
{
	kptscand = kthread_run(kptscand_main, NULL, "kptscand");
	if (IS_ERR(kptscand)) {
		pr_err("Failed to create kptscand\n");
		return PTR_ERR(kptscand);
	}
	return 0;
}

static void __exit pt_scanner_exit(void)
{
	kthread_stop(kptscand);	
}

module_init(pt_scanner_init);
module_exit(pt_scanner_exit);

MODULE_AUTHOR("Minho Kim <mhkim@dgist.ac.kr>");
MODULE_DESCRIPTION("Page Table scanner");
MODULE_LICENSE("GPL v2");

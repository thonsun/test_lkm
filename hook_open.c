/**
 * @file    nice.c
 * @author  WingLim
 * @date    2020-03-05
 * @version 0.1
 * @brief  读取及修改一个进程的 nice 值，并返回最新的 nice 值及优先级 prio 的模块化实现
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
// 下面这些头文件为自定义系统调用要用到的
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>

// 这里是随便挑了一个系统调用来劫持，224 为 timer_gettime
#define the_syscall_num 224

MODULE_LICENSE("GPL");
MODULE_AUTHOR("WingLim");
MODULE_DESCRIPTION("A module to read or set nice value");
MODULE_VERSION("0.1");

// 用于保存 sys_call_table 地址
unsigned long **sys_call_table;
// 用于保存被劫持的系统调用
static int (*anything_saved)(void);

// 从内核起始地址开始搜索内存空间来获得 sys_call_table 的内存地址
unsigned long **get_sys_call_table(void)
{
  unsigned long **entry = (unsigned long **)PAGE_OFFSET;

  for (;(unsigned long)entry < ULONG_MAX; entry += 1) {
    if (entry[__NR_close] == (unsigned long *)sys_close) {
        return entry;
      }
  }
  return NULL;
}

void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
}

void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}

// 这个是用来获取进程的 prio，代码来自 task_prio
// 因为这个函数没有导出，所以拷贝一份到源码里
int get_prio(const struct task_struct *p)
{
        return p->prio - MAX_RT_PRIO;
}

asmlinkage long sys_setnice(pid_t pid, int flag, int nicevalue, int __user * prio, int __user * nice)
{
    struct pid * kpid;
        struct task_struct * task;
        int nicebef;
    int priobef;
        kpid = find_get_pid(pid); // 获取 pid
        task = pid_task(kpid, PIDTYPE_PID); // 返回 task_struct
        nicebef = task_nice(task); // 获取进程当前 nice 值
    priobef = get_prio(task); // 获取进程当前 prio 值

        if(flag == 1){
                set_user_nice(task, nicevalue);
                printk("nice value edit before：%d\tedit after：%d\n", nicebef, nicevalue);
                return 0;
        }
        else if(flag == 0){
                copy_to_user(nice, (const void*)&nicebef, sizeof(nicebef));
                copy_to_user(prio, (const void*)&priobef, sizeof(priobef));
                printk("nice of the process：%d\n", nicebef);
                printk("prio of the process：%d\n", priobef);
                return 0;
        }

        printk("the flag is undefined!\n");
        return EFAULT;
}

static int __init init_addsyscall(void)
{
    // 关闭写保护
    disable_write_protection();
    // 获取系统调用表的地址
    sys_call_table = get_sys_call_table();
    // 保存原始系统调用的地址
    anything_saved = (int(*)(void)) (sys_call_table[the_syscall_num]);
    // 将原始的系统调用劫持为自定义系统调用
    sys_call_table[the_syscall_num] = (unsigned long*)sys_setnice;
    // 恢复写保护
    enable_write_protection();
    printk("hijack syscall success\n");
    return 0;
}

static void __exit exit_addsyscall(void) {
    // 关闭写保护
    disable_write_protection();
    // 恢复原来的系统调用
    sys_call_table[the_syscall_num] = (unsigned long*)anything_saved;
    // 恢复写保护
    enable_write_protection();
    printk("resume syscall\n");
}

module_init(init_addsyscall);
module_exit(exit_addsyscall);
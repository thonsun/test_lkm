#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
// 下面这些头文件为自定义系统调用要用到的
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>

// 这里是随便挑了一个系统调用来劫持
#define sys_open_syscall_num 2

MODULE_LICENSE("GPL");
MODULE_AUTHOR("thonsun");
MODULE_DESCRIPTION("A module to hook sys_open");
MODULE_VERSION("v0.1.0");

// 用于保存 sys_call_table 地址
unsigned long **sys_call_table;
// 用于保存被劫持的系统调用
asmlinkage long
(*real_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long
fake_open(const char __user *filename, int flags, umode_t mode);

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

asmlinkage long
fake_open(const char __user *filename, int flags, umode_t mode)
{
    if ((flags & O_CREAT) && strcmp(filename, "/dev/null") != 0) {
        printk("open: %s\n", filename);
    }

    return real_open(filename, flags, mode);
}

static int __init init_addsyscall(void)
{
    // 关闭写保护
    disable_write_protection();
    // 获取系统调用表的地址
    sys_call_table = get_sys_call_table();
    printk("sys_call_table:%p\n",sys_call_table)
    // 保存原始系统调用的地址
    real_open = (int(*)(void)) (sys_call_table[sys_open_syscall_num]);
    // 将原始的系统调用劫持为自定义系统调用
    sys_call_table[the_syscall_num] = (unsigned long*)fake_open;
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
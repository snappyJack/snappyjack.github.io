---
layout: post
title: Seccomp and Ptrace
excerpt: "Seccomp and Ptrace"
categories: [未完待续]
comments: true
---

#### Seccomp
securecomputing ,linux下的sandbox,限制哪些syscall可以使用
```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

int main(){
	struct sock_fprog prog;

	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
```
#### Seccomp Filter
Allow All Syscall
```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdlib.h>

int main(){
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),//SECCOMP_RET_KILL 所有都不给过
	};
	
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};
	

	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	
	system("ls");
}
```
编译
```bash
gcc -g sec.c -o sec 
```
运行
```
./sec 
sec  sec.c
```
Disable All Syscall
```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdlib.h>

int main(){
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
	};
	
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};
	

	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	
	system("ls");
}
```
gdb dump memory
```
gdb-peda$ dump memory dd 0x00007fffffffe2a0 0x00007fffffffe2a0+8
```

使用libseccomp,地址`https://github.com/seccomp/libseccomp`,编译并copy`scmp_bpf_disasm`
```
./scmp_bpf_disasm < dd
 line  OP   JT   JF   K
=================================
 0000: 0x06 0x00 0x00 0x00000000   ret KILL
```
Disable execv
```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdlib.h>

int main(){
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),		//load进system number
		BPF_JUMP(BPF_JMP+BPF_JEQ,59,1,0),		//等于59就跳过一行
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
	};
	
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};
	

	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	
	printf("####\n");
	system("ls");
}
```
运行
```
./sec 
####
```
#### Bypass Seccomp
- 没有检查arch
- 没有挡掉x32下的syscall number

以下函数可以在x86-64和i386之间做切换(切换之后syscall 的number号变化了)
```
to32:
	mov DWORD [rsp+4] ,0x23
	retf
	
to64:
	mov DWORD [esp+4], 0x33
	retf
```

**x32 syscall**:x32是在x86-64下的一种特殊模式

##### Ptrace
ptrace也可以拦截特定的事件
1.36

---
layout: post
title: 通过chained return-to-libc绕过NX
excerpt: "sploitfun系列教程之2.2 chained return-to-libc"
categories: [sploitfun系列教程]
comments: true
---

漏洞代码
```c
//vuln.c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
 char buf[256];
 seteuid(getuid()); /* Temporarily drop privileges */
 strcpy(buf,argv[1]);
 printf("%s",buf);
 fflush(stdout);
 return 0;
}
```
编译
```
gcc -fno-stack-protector -g -o vuln vuln.c
gcc -fno-stack-protector -g -o vuln vuln.c -m32
chmod 777 vuln
```
现在我们面临两个问题

- libc地址和参数需要以特定的结构叠放在栈空间，多个libc地址和参数无法同时叠放在一起
- seteuid_arg这个参数值应该是0，但是strcpy()函数的特性，不会讲`\x00`之后的参数拷贝到栈中

为了解决第一个问题我们使用了这两个技术
1. ESP Lifting
2. Frame Faking

#### 什么是Frame Faking?
Frame Faking不是使用libc函数地址（本例中为seteuid）直接覆盖返回地址，而是使用`leave ret`指令来覆盖它。这样避免了参数的重叠，使多个function及参数值的叠放成为了可能，首先我们看一下需要构造的栈空间的结构
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/chanined-return-to-libc.png)

leave指令
```
mov esp,ebp            //esp = ebp
pop ebp                //ebp = *esp
```
ret指令 :  `pop eip`

main函数中的最后两条指令
```
(gdb) disassemble main
   0x0804854f <+82>:	mov    eax,0x0
   0x08048554 <+87>:	leave  
   0x08048555 <+88>:	ret    
End of assembler dump
```
Before main’s epilogue executed, as shown in the above stack layout, attacker would have overflown the buffer and would have overwritten, main’s ebp with fake_ebp0 (0xbffff204) and return address with “leave ret” instruction address (0x0804851c). Now when CPU is about to execute main’s epilogue,  EIP points to text address 0x0804851c (“leave ret”). On execution, following happens:

- leave’ changes following registers
	- esp = ebp = 0xbffff1f8
	- ebp = 0xbffff204, esp = 0xbffff1fc
- ‘ret’ executes “leave ret” instruction (located at stack address 0xbffff1fc) .

seteuid: Now again EIP points to text address 0x0804851c (“leave ret”). On execution, following happens:

- ‘leave’ changes following registers
	- esp = ebp = 0xbffff204
	- ebp = 0xbffff214, esp =0xbffff208
- ‘ret’ executes seteuid() (located at stack address 0xbffff208). To invoke seteuid successfully, seteuid_arg should be placed at offset 8 from seteuid_addr ie) at stack address 0xbffff210
- After seteuid() gets invoked, “leave ret” instruction (located at stack address 0xbffff20c), gets executed.

这样我们的程序就可以实现多个函数调用了

第二个问题，seteuid_arg应为零。如何在堆栈地址0xbffff210写入0？There is a simple solution to it, which is discussed by nergal in the same article. While chaining libc functions, first few calls should be strcpy which copies a NULL byte into seteuid_arg’s stack location.

NOTE: But unfortunately in my libc.so.6 strcpy’s function address is 0xb7ea6200 – ie) libc function address itself contains a NULL byte (bad character!!). Hence strcpy cant be used to successfully exploit the vulnerable code. sprintf (whose function address is 0xb7e6e8d0) is used as a replacement for strcpy ie) using sprintf NULL byte is copied in to seteuid_arg’s stack location.

Thus following libc functions are chained to solve the above two problems and to successfully obtain root shell:
```
sprintf | sprintf | sprintf | sprintf | seteuid | system | exit
```


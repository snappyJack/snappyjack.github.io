---
layout: post
title: userfaltfd在内核中的利用
excerpt: "kernel pwn"
categories: [未完待续]
comments: true
---

未完待续
#### 简单理解
userfaultfd是linux下的一直缺页处理机制，用户可以自定义函数来处理这种事件。所谓的缺页，就是所访问的页面还没有装入RAM中。比如mmap创建的堆，它实际上还没有装载到内存中，系统有自己默认的机制来处理，用户也可以自定义处理函数，在处理函数没有结束之前，缺页发生的位置将处于暂停状态。这将非常有助于条件竞争的利用。

举例如下
```
    if (ptr) {  
       ...  
       copy_from_user(ptr,user_buf,len);  
       ...  
    }  
```
如果，我们的user_buf是一块mmap映射的，并且未初始化的区域，此时就会触发缺页错误，copy_from_user将暂停执行，在暂停的这段时间内，我们开另一个线程，将ptr释放掉，再把其他结构申请到这里（比如tty_struct），然后当缺页处理结束后，copy_from_user恢复执行，然而ptr此时指向的是tty_struct结构，那么就能对tty_struct结构进行修改了。虽然说，不用缺页处理，也能造成条件竞争，但是几率比较小。而利用了缺页处理，几率将增加很大很大。


#### 相关知识

### 页调度与延迟加载
有的内存既不在RAM也不在交换区，例如mmap创建的内存映射页。mmap页在read/write访问之前，实际上还没有创建（还没有映射到实际的物理页），例如：`mmap(0x1337000, 0x1000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE, fd, 0);`

内核并未将fd内容拷贝到0x1337000，只是将地址0x1337000映射到文件fd。

当有如下代码访问时：
```
char *a = (char *)0x1337000
printf("content: %c\n", a[0]);
```
若发生对该页的引用，则（1）为0x1337000创建物理帧，（2）从fd读内容到0x1337000，（3）并在页表标记合适的入口，以便识别0x1337000虚地址。如果是堆空间映射，仅第2步不同，只需将对应物理帧清0。

总之，若首次访问mmap创建的页，会耗时很长，会导致上下文切换和当前线程的睡眠。

### 别名页 Alias pages
没有API能直接访问物理页，但内核有时需要修改物理帧的值（例如修改页表入口），于是引入了别名页，将物理帧映射到虚拟页。在每个线程的启动和退出的页表中，所以大多数物理帧有两个虚拟页映射到它，这就是“别名”的由来。通常别名页的地址是SOME_OFFSET + physical address。

### userfaultfd
userfaultfd机制可以让用户来处理缺页，可以在用户空间定义自己的`page-fault handler`

##### Step 1: 创建一个描述符uffd
所有的注册内存区间、配置和最终的缺页处理等就都需要用ioctl来对这个uffd操作。ioctl-userfaultfd支持UFFDIO_API、UFFDIO_REGISTER、UFFDIO_UNREGISTER、UFFDIO_COPY、UFFDIO_ZEROPAGE、UFFDIO_WAKE等选项。比如UFFDIO_REGISTER用来向userfaultfd机制注册一个监视区域，这个区域发生缺页时，需要用UFFDIO_COPY来向缺页的地址拷贝自定义数据。
```
# 2 个用于注册、注销的ioctl选项：
UFFDIO_REGISTER                 注册将触发user-fault的内存地址
UFFDIO_UNREGISTER               注销将触发user-fault的内存地址
# 3 个用于处理user-fault事件的ioctl选项：
UFFDIO_COPY                     用已知数据填充user-fault页
UFFDIO_ZEROPAGE                 将user-fault页填零
UFFDIO_WAKE                     用于配合上面两项中 UFFDIO_COPY_MODE_DONTWAKE 和
                                UFFDIO_ZEROPAGE_MODE_DONTWAKE模式实现批量填充  
# 1 个用于配置uffd特殊用途的ioctl选项：
UFFDIO_API                      它又包括如下feature可以配置：
                                UFFD_FEATURE_EVENT_FORK         (since Linux 4.11)
                                UFFD_FEATURE_EVENT_REMAP        (since Linux 4.11)
                                UFFD_FEATURE_EVENT_REMOVE       (since Linux 4.11)
                                UFFD_FEATURE_EVENT_UNMAP        (since Linux 4.11)
                                UFFD_FEATURE_MISSING_HUGETLBFS  (since Linux 4.11)
                                UFFD_FEATURE_MISSING_SHMEM      (since Linux 4.11)
                                UFFD_FEATURE_SIGBUS             (since Linux 4.14)
```

```
// userfaultfd系统调用创建并返回一个uffd，类似一个文件的fd
uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
```
##### STEP 2. 用ioctl的UFFDIO_REGISTER选项注册监视区域
```
// 注册时要用一个struct uffdio_register结构传递注册信息:
// struct uffdio_range {
// __u64 start;    /* Start of range */
// __u64 len;      /* Length of range (bytes) */
// };
//
// struct uffdio_register {
// struct uffdio_range range;
// __u64 mode;     /* Desired mode of operation (input) */
// __u64 ioctls;   /* Available ioctl() operations (output) */
// };

addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
// addr 和 len 分别是我匿名映射返回的地址和长度，赋值到uffdio_register
uffdio_register.range.start = (unsigned long) addr;
uffdio_register.range.len = len;
// mode 只支持 UFFDIO_REGISTER_MODE_MISSING
uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
// 用ioctl的UFFDIO_REGISTER注册
ioctl(uffd, UFFDIO_REGISTER, &uffdio_register);
```
##### STEP 3. 创建一个处理专用的线程轮询和处理”user-fault”事件
要使用userfaultfd，需要创建一个处理专用的线程轮询和处理”user-fault”事件。主进程中就要调用pthread_create创建这个自定义的handler线程：
```
// 主进程中调用pthread_create创建一个fault handler线程
pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
```
一个自定义的线程函数举例如下，这里处理的是一个普通的匿名页用户态缺页，我们要做的是把我们一个已有的一个page大小的buffer内容拷贝到缺页的内存地址处。用到了poll函数轮询uffd，并对轮询到的UFFD_EVENT_PAGEFAULT事件(event)用拷贝(ioctl的UFFDIO_COPY选项)进行处理。

注意：如果写exp只需处理一次缺页，可以不用循环。
```
static void * fault_handler_thread(void *arg)
{    
    // 轮询uffd读到的信息需要存在一个struct uffd_msg对象中
    static struct uffd_msg msg;
    // ioctl的UFFDIO_COPY选项需要我们构造一个struct uffdio_copy对象
    struct uffdio_copy uffdio_copy;
    uffd = (long) arg;
      ......
    for (;;) { // 此线程不断进行polling，所以是死循环
        // poll需要我们构造一个struct pollfd对象
        struct pollfd pollfd;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        poll(&pollfd, 1, -1);
        // 读出user-fault相关信息
        read(uffd, &msg, sizeof(msg));
        // 对于我们所注册的一般user-fault功能，都应是UFFD_EVENT_PAGEFAULT这个事件
        assert(msg.event == UFFD_EVENT_PAGEFAULT);
        // 构造uffdio_copy进而调用ioctl-UFFDIO_COPY处理这个user-fault
        uffdio_copy.src = (unsigned long) page;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        // page(我们已有的一个页大小的数据)中page_size大小的内容将被拷贝到新分配的msg.arg.pagefault.address内存页中
        ioctl(uffd, UFFDIO_COPY, &uffdio_copy);
          ......
    }
}
```
### 漏洞分析
##### 1.init_module()函数
```
void init_module()
{
  bufPtr = bufStart;
  return misc_register(&dev);
}
```
dev是struct miscdevice结构,如下
```
struct miscdevice  {
    int minor;
    const char *name;
    const struct file_operations *fops;
    struct list_head list;
    struct device *parent;
    struct device *this_device;
    const struct attribute_group **groups;
    const char *nodename;
    umode_t mode;
};
```
在IDA中看dev结构，dev_name是"note"，fops指向0x680处。如下
```
.data:0000000000000620 dev             db  0Bh                 ; DATA XREF: init_module+5↑o
.data:0000000000000620                                         ; cleanup_module+5↑o
.data:0000000000000621                 db    0
.data:0000000000000622                 db    0
.data:0000000000000623                 db    0
.data:0000000000000624                 db    0
.data:0000000000000625                 db    0
.data:0000000000000626                 db    0
.data:0000000000000627                 db    0
.data:0000000000000628                 dq offset aNote         ; "note"
.data:0000000000000630                 dq offset unk_680
.data:0000000000000638                 align 80h
.data:0000000000000680 unk_680         db    0                 ; DATA XREF: .data:0000000000000630↑o
```
file_operations结构如下
```
// file_operations结构
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
    int (*iopoll)(struct kiocb *kiocb, bool spin);
    int (*iterate) (struct file *, struct dir_context *);
    int (*iterate_shared) (struct file *, struct dir_context *);
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);

    ... truncated
};
```

其中`unk_680`对应`file_operations`结构，发现只定义了open和unlocked_ioctl函数，其他都是null。unlocked_ioctl和compat_ioctl有区别，unlocked_ioctl不使用内核提供的全局同步锁，所有的同步原语需自己实现，所以可能存在条件竞争漏洞。

##### 2.unlocked_ioctl()函数
unlocked_ioctl()函数实现4个功能：new/edit/show/delete。
```
// 从用户缓冲区userPtr拷贝参数到req结构, note length / note content
void * unlocked_ioctl(file *f, int operation, void *userPtr)
{
  char encBuffer[0x20];
  struct noteRequest req;

  memset(encBuffer, 0, sizeof(encBuffer));
  if ( copy_from_user(&req, userPtr, sizeof(req)) )
    return -14;
  /* make note, view note, edit note, delete note */
  return result;
}
```

```
// noteRequest结构——用户参数
struct noteRequest{
  size_t idx;
  size_t length;
  size_t userptr;
}
// note结构——存储的note
struct note {
    unsigned long key;
    unsigned char length;
    void *contentPtr;
    char content[];
}
```
new note功能, `operation == -256`
```
//(1) new note功能, operation == -256
/* 创建note，从bufPtr分配空间，从current_task获取key(task_struct.mm->pgd,页全局目录的存放位置)，对content进行XOR加密。最后将(&note->content - page_offset_base)值保存，别名页的地址是【SOME_OFFSET + physical address】，page_offset_base就是这个SOME_OFFSET。没开kaslr时，page_offset_base固定，否则随机化。
注意：length长度范围是0~0x100，从汇编指令可看出来`movzx   ecx, byte ptr [rsp+140h+req.length]`，是byte级赋值操作。
*/
    if ( operation == -256 )
    {
        idx = 0;
        while ( 1 )
        {
          if (!notes[idx])
            break;
        if (++idx == 16)
            return -14LL;
        } // 从全局数组notes找到空位，最多16个note

    new = (note *)bufPtr;
    req.noteIndex = idx;
    notes[idx] = (struct note *)bufPtr;
    new->length = req.noteLength;
    new->key = *(void **)(*(void **)(__readgsqword((unsigned __int64)&current_task) + 0x7E8) + 80);// ????
    bufPtr = &new->content[req.length];

    if ( req.length > 0x100uLL )
    {
      _warn_printk("Buffer overflow detected (%d < %lu)!\n", 256LL, req.length);
      BUG();
    }

    _check_object_size(encBuffer, req.length, 0LL);
    copy_from_user(encBuffer, userptr, req.length);
    length = req.length;

    if ( req.length )
    {
      i = 0LL;
      do
      {
        encBuffer[i / 8] ^= new->key;         // encryption
        i += 8LL;
      }
      while ( i < length );
    }

    memcpy(new->content, encBuffer, length);
    new->contentPtr = &new->content[-page_offset_base];// 注意 page_offset_base
    return 0;
```
delete功能
```
//(2) delete功能：清空note数组，把bufPtr指向全局缓冲区开头，并清0。
ptr = notes;
if (operation == -253)
{
do                  
{
  *ptr = 0LL;
  ++ptr;
}
while (ptr < note_end);

bufPtr = bufStart;
memset(bufStart, 0, sizeof(bufStart));  
return 0;
```
edit功能
```
// (3) edit功能。注意copy_from_user很耗时，能增大race的成功率
if (operation == -255)
{
    note = notes[idx];
    if ( note )
    {
    length = note->length;
    userptr = req.userptr;
    contentPtr = (note->contentPtr + page_offset_base);
    _check_object_size(encBuffer, length, 0LL);
    copy_from_user(encBuffer, userptr, length);
    if ( length )
        {
            i = 0;
            do
            {
              encBuffer[i/8] ^= note->key;
              i += 8LL;
            }
            while (length > i);                    
            memcpy(contentPtr, encBuffer, length)
        }
    return 0LL;
    }
}
```
show功能
```
// (4) show功能。将content用XOR解密后用copy_to_user打印出来。
if ( (_DWORD)operation == -254 )
{
  tmp_note2 = (note *)global_notes[note_idx2];
    result = 0LL;
    if ( tmp_note2 )
    {
      len = LOBYTE(tmp_note2->length);          
      contentPtr2 = (_DWORD *)(tmp_note2->contentPtr + page_offset_base);
      memcpy(encBuffer, contentPtr, len)
    }
  if ( len )
  {
     ji_2 = 0LL;
     do
     {
       encBuffer[ji_2 / 8] ^= tmp_note2->key;
       ji_2 += 8LL;
     }
     while ( ji_2 < len );
   }
   userptr = req.userptr;
   _check_object_size(encBuffer, len, 1LL);
   copy_to_user(userptr, encBuffer, len);
   result = 0LL;
}
```
##### 漏洞利用分析
考虑以下两线程：
```
thread 1								thread 2(理解为自我定义的pagefaultfd)
edit note 0 (size 0x10)					idle(空闲)
copy_from_user							idle(空闲)
idle(空闲)								delete all notes
idle(空闲)								add note 0 with size 0x0
idle(空闲)								add note 1 with size 0x0
continue edit of note 0 (size 0x10)		idle(空闲)
```
由于edit时copy_from_user首次访问mmap地址，触发缺页处理函数，等线程2删除所有note并重新添加两个note后，线程1才继续编辑note 0，此时的编辑content size还是0x10，所以就会产生溢出。

### 漏洞利用
##### 1.利用方法
目标：若伪造note结构，就能构造任意地址读写。
```
// note结构
struct note {
    unsigned long key;
    unsigned char length;
    void *contentPtr;
    char content[];
}
```
key值泄露：若读取note 0，则会将加密后的null字节也打印出来，其实就是key值。
```
0x0					note 0, with content size 0x10
0x18				note 1
0x30				NULL’ed out data
```
module基址泄露：得到key后，可以得到contentPtr值，contentPtr须加上page_base_offset才是真实指针。就能以module的.bss相对地址进行任意读写，可读出notes数组从而泄露module基址。

内核基址泄露：可读取module的0x6c处的.text:000000000000006C call _copy_from_user来泄露内核基址。

page_offset_base泄露：读取.text:00000000000001F7 mov r12, cs:page_offset_base处的4字节偏移page_offset_base_offset，再读取page_offset_base_offset + 0x1fe + mudule_base处的值，就是page_offset_base的值。为什么非要泄露它呢，因为读/写都是以它为基地址。
```
// 泄露内核基址：读取0x6c处的值，取出32位offset，加上pc即可得到copy_from_user函数地址。
unsigned long leak = read64(0x6c + moduleBase);
long int offset = *((int *)(((char *)&leak) + 1)) + 5;
copy_from_user = offset + moduleBase + 0x6c;
```
##### 2.exploit
为了准确控制线程1在copy_from_user或copy_to_user处停住，需用到userfaultfd（处理用户空间的页错误）。注意本题的漏洞根本原因在于使用了unlocked_ioctl，对全局数组notes进行访问时没有上锁，所以才能用userfaultfd在copy_from_user处暂停。

##### 触发溢出步骤：

1. 创建1个content length长度为0x10的note。
2. 创建1个userfalut fd，来监视0x1337000地址处的页错误。
3. 对note0 进行edit，并利用mmap将传进去的userptr指针指向0x1337000地址空间。
4. 在edit note0执行到copy_from_user时，进入页错误处理程序。
5. 在错误处理程序中，清空notes，并创建note0/note1，content length都是0。
6. 恢复执行edit note0，将note1的content length覆盖为0xf0。
7. 触发溢出。

##### 利用步骤：
1. 泄露key：输出note1，content内容为NULL，输出内容会与key异或，仍为key。
2. 泄露module_base：创建note2，输出note1，会输出note2的contentPtr指针，即可计算出module_base。
3. 泄露page_offset_base：edit note1，将note2的contentPtr改成module_base+0x1fa，.text:00000000000001F7 mov r12, cs:page_offset_base，show note2泄露page_offset_base在module中的偏移page_offset_base_offset；edit note，将note2的contentPtr改成module_base+0x1fe+page_offset_base_offset，泄露出page_offset_base。
4. 搜索cred地址：利用prctl的PR_SET_NAME功能搜索到task_struct结构，（满足条件：real_cred—NAME前0x10处和cred—NAME前0x8处指针值相等且位于内核空间，大于0xffff000000000000）；将note2的contentPtr覆盖为cred_addr-page_offset_base+4。
5. 修改cred提权。
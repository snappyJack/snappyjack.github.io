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

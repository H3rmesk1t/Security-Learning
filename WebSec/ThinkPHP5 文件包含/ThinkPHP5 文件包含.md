# ThinkPHP5 文件包含

Author: H3rmesk1t

Data: 2021.08.16

# 漏洞概要
- 本次漏洞存在于 ThinkPHP 模板引擎中，在加载模版解析变量时存在变量覆盖问题，而且程序没有对数据进行很好的过滤，最终导致文件包含漏洞的产生
- 漏洞影响版本： 5.0.0<=ThinkPHP<=5.0.21 、 5.1.3<=ThinkPHP5<=5.1.25
# 初始配置
- 获取测试环境代码

```bash
composer create-project --prefer-dist topthink/think=5.0.18  tpH3rmesk1t
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/ca08f62525a14813aaae9f8fd5035a2b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

- 将 `composer.json` 文件的 `require` 字段设置成如下

```bash
"require": {
    "php": ">=5.6.0",
    "topthink/framework": "5.0.18"
},
```

然后执行 `composer update` ，并将 `application/index/controller/Index.php` 文件代码设置如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/94875f2b53d54bec92789f706ad15e6b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
namespace app\index\controller;
use think\Controller;
class Index extends Controller
{
    public function index()
    {
        $this->assign(request()->get());
        return $this->fetch(); // 当前模块/默认视图目录/当前控制器（小写）/当前操作（小写）.html
    }
}
```

创建 application/index/view/index/index.html 文件，内容随意（没有这个模板文件的话，在渲染时程序会报错）

![在这里插入图片描述](https://img-blog.csdnimg.cn/7fdb582b76c74e81be0a0bf509f0a824.png#pic_center)
# 漏洞利用

将图片马 demo.jpg 放至 public 目录下（模拟上传图片操作），访问

```bash
http://127.0.0.1/cms/public/index.php/index/index?cacheFile=demo.jpg
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/f829190d237a4b8291ef776f1b861f0b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 漏洞分析

首先，用户可控数据未经过滤，直接通过 `Controller` 类的 `assign` 方法进行模板变量赋值，并将可控数据存在 `think\View` 类的 `data` 属性中

![在这里插入图片描述](https://img-blog.csdnimg.cn/f755c082abd24a6f9be4795ebb8fc5fe.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

接着程序开始调用 `fetch` 方法加载模板输出，这里如果我们没有指定模板名称，其会使用默认的文件作为模板，模板路径位：`当前模块/默认视图目录/当前控制器(小写)/当前操作(小写).html` ，如果默认路径模板不存在，程序就会报错，跟进到 `thinkphp/library/think/View.php`

![在这里插入图片描述](https://img-blog.csdnimg.cn/39a3076073684bc2a2037ff2e0fc5494.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/b68253b1d486465a9fabc9b8468f0d95.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9d6755110aa4436996e391d33b094df2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

我们跟进到 `Template` 类的 `fetch` 方法，可以发现可控变量 `$vars` 赋值给 `$this->data` 并最终传入 `File` 类的 `read` 方法，而 `read` 方法中在使用了 `extract` 函数后，直接包含了 `$cacheFile` 变量，这里就是漏洞发生的关键原因，因为 `extract` 函数中的参数 `$vars` 可以由用户控制，可以通过 `extract` 函数，直接覆盖 `$cacheFile` 变量

![在这里插入图片描述](https://img-blog.csdnimg.cn/55bb98ce05314698999f85c76ed5599a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b2b729e5cc8642158a15235c4da0e1eb.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

完整的方法调用，从下往上

![在这里插入图片描述](https://img-blog.csdnimg.cn/c8df6e31e3f94a32895df609c5261e3e.png#pic_center)


# 漏洞修复

官方的修复方法是：先将 `$cacheFile` 变量存储在 `$this->cacheFile` 中，在使用 `extract` 函数后，最终 include 的变量是 `$this->cacheFile` ，这样也就避免了 include 被覆盖后的变量值

![在这里插入图片描述](https://img-blog.csdnimg.cn/1de15b226d7a44408aa085921ef11b59.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 攻击总结

参考Mochazz师傅的审计流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/1a7a51e928e641ffb3c2d5529fd8bc45.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
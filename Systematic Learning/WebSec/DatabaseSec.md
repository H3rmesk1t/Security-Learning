# Database Security Knowledge

Author: H3rmesk1t

# MySQL
## 简介
`MySQL`是一个关系型数据库管理系统, 由瑞典`MySQL AB`公司开发, 目前属于`Oracle`公司. `MySQL`是一种关联数据库管理系统, 关联数据库将数据保存在不同的表中, 而不是将所有数据放在一个大仓库内, 这样就增加了速度并提高了灵活性. 

一个完整的`MySQL`管理系统结构通常如下图所示, 在图中可以看到: `MySQL`可以管理多个数据库, 一个数据库又可以包含多个数据表, 而一个数据表中又含有多条字段, 一行数据是多个字段同一行的一串数据.

<div align=center><img src="./images/1.png"></div>

## 常见漏洞
随着`Web`安全的不断发展, 在`MySQL`中, 越来越多的漏洞利用方式被挖掘出来, 常见的漏洞利用方式有: `SQL`注入漏洞、身份认证漏洞、拒绝服务攻击、`PHPMyAdmain`万能密码登录、`MySQL`提权.

<div align=center><img src="./images/2.png"></div>
<div align=center><img src="./images/3.png"></div>
<div align=center><img src="./images/4.png"></div>
<div align=center><img src="./images/5.png"></div>
<div align=center><img src="./images/6.png"></div>
<div align=center><img src="./images/7.png"></div>
<div align=center><img src="./images/8.png"></div>
<div align=center><img src="./images/9.png"></div>
<div align=center><img src="./images/10.png"></div>
<div align=center><img src="./images/11.png"></div>
<div align=center><img src="./images/12.png"></div>
<div align=center><img src="./images/13.png"></div>
<div align=center><img src="./images/14.png"></div>
<div align=center><img src="./images/15.png"></div>
<div align=center><img src="./images/16.png"></div>
<div align=center><img src="./images/17.png"></div>
<div align=center><img src="./images/18.png"></div>
<div align=center><img src="./images/19.png"></div>
<div align=center><img src="./images/20.png"></div>
<div align=center><img src="./images/21.png"></div>
<div align=center><img src="./images/22.png"></div>
<div align=center><img src="./images/23.png"></div>
<div align=center><img src="./images/24.png"></div>
<div align=center><img src="./images/25.png"></div>
<div align=center><img src="./images/26.png"></div>
<div align=center><img src="./images/27.png"></div>
<div align=center><img src="./images/28.png"></div>
<div align=center><img src="./images/29.png"></div>
<div align=center><img src="./images/30.png"></div>
<div align=center><img src="./images/31.png"></div>
<div align=center><img src="./images/32.png"></div>
<div align=center><img src="./images/33.png"></div>
<div align=center><img src="./images/34.png"></div>
<div align=center><img src="./images/35.png"></div>
<div align=center><img src="./images/36.png"></div>
<div align=center><img src="./images/37.png"></div>
<div align=center><img src="./images/38.png"></div>
<div align=center><img src="./images/39.png"></div>
<div align=center><img src="./images/40.png"></div>
<div align=center><img src="./images/41.png"></div>
<div align=center><img src="./images/42.png"></div>
<div align=center><img src="./images/43.png"></div>
<div align=center><img src="./images/44.png"></div>
<div align=center><img src="./images/45.png"></div>
<div align=center><img src="./images/46.png"></div>
<div align=center><img src="./images/47.png"></div>
<div align=center><img src="./images/48.png"></div>
<div align=center><img src="./images/49.png"></div>
<div align=center><img src="./images/50.png"></div>
<div align=center><img src="./images/51.png"></div>
<div align=center><img src="./images/52.png"></div>
<div align=center><img src="./images/53.png"></div>
<div align=center><img src="./images/54.png"></div>
<div align=center><img src="./images/55.png"></div>
<div align=center><img src="./images/56.png"></div>
<div align=center><img src="./images/57.png"></div>
<div align=center><img src="./images/58.png"></div>
<div align=center><img src="./images/59.png"></div>
<div align=center><img src="./images/60.png"></div>
<div align=center><img src="./images/61.png"></div>
<div align=center><img src="./images/62.png"></div>
<div align=center><img src="./images/63.png"></div>
<div align=center><img src="./images/64.png"></div>
<div align=center><img src="./images/65.png"></div>
<div align=center><img src="./images/66.png"></div>
<div align=center><img src="./images/67.png"></div>
<div align=center><img src="./images/68.png"></div>
<div align=center><img src="./images/69.png"></div>
<div align=center><img src="./images/70.png"></div>
<div align=center><img src="./images/71.png"></div>
<div align=center><img src="./images/73.png"></div>
<div align=center><img src="./images/74.png"></div>
<div align=center><img src="./images/75.png"></div>
<div align=center><img src="./images/76.png"></div>
<div align=center><img src="./images/77.png"></div>
<div align=center><img src="./images/78.png"></div>
<div align=center><img src="./images/79.png"></div>
<div align=center><img src="./images/80.png"></div>
<div align=center><img src="./images/81.png"></div>
<div align=center><img src="./images/82.png"></div>
<div align=center><img src="./images/83.png"></div>
<div align=center><img src="./images/84.png"></div>
<div align=center><img src="./images/85.png"></div>
<div align=center><img src="./images/86.png"></div>
<div align=center><img src="./images/87.png"></div>
<div align=center><img src="./images/88.png"></div>
<div align=center><img src="./images/89.png"></div>
<div align=center><img src="./images/90.png"></div>
<div align=center><img src="./images/91.png"></div>
<div align=center><img src="./images/92.png"></div>
<div align=center><img src="./images/93.png"></div>
<div align=center><img src="./images/94.png"></div>
<div align=center><img src="./images/95.png"></div>
<div align=center><img src="./images/96.png"></div>
<div align=center><img src="./images/97.png"></div>
<div align=center><img src="./images/98.png"></div>
<div align=center><img src="./images/99.png"></div>
<div align=center><img src="./images/100.png"></div>
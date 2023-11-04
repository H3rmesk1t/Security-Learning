# Python安全学习—Django SQL注入漏洞

Author: H3rmesk1t

Data: 2022.06.01

# 前言
考试前翻`Python`的组件漏洞时看到过`Django`存在`SQL`注入漏洞, 考完后抽空分析几个相关的漏洞, 分别是`CVE-2020-7471`、`CVE-2021-35042`和`CVE-2022-28346`.


# Django 简介
Django is a high-level Python web framework that encourages rapid development and clean, pragmatic design. Built by experienced developers, it takes care of much of the hassle of web development, so you can focus on writing your app without needing to reinvent the wheel. It’s free and open source.

<div align=center><img src="./images/1.png"></div>

# CVE-2020-7471
## 漏洞简介
Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.

<div align=center><img src="./images/2.png"></div>

## 漏洞环境
 - 参考搭建好的环境[CVE-2020-7471](https://github.com/H3rmesk1t/Django-SQL-Inject-Env/tree/main/CVE-2020-7471).

## 漏洞分析
在漏洞描述中说明该漏洞的核心是`StringAgg`聚合函数的`delimiter`参数存在`SQL`注入漏洞. 通过查找`Django`的`commit`记录, 在官方对的修复代码中可以看到, 漏洞函数位于`from django.contrib.postgres.aggregates import StringAgg`模块之中.

<div align=center><img src="./images/3.png"></div>

官方修复通过引入`from django.db.models import Value`中的`Value`来处理来防御该注入漏洞:

```python
delimiter_expr = Value(str(delimiter))
```

跟进`django.db.models`中的`Value`函数, 在注释中可以看到, `Value`函数会将处理过后的参数加入到`sql parameter list`, 之后会进过`Django`内置过滤机制的过滤, 从而来防范`sql`注入漏洞.

<div align=center><img src="./images/4.png"></div>

由于漏洞点是位于`StringAgg`聚合函数的`delimiter`参数, 在官方文档中对该聚合函数进行了说明, 简单来说它会将输入的值使用`delimiter`分隔符级联起来.

<div align=center><img src="./images/5.png"></div>

通过`Fuzz`发现`delimiter`为单引号时会引发报错, 且通过打印出的报错信息可以看到, 单引号未经过任何转义就嵌入到了`sql`语句中.

```python
def fuzz():
    symbol_str = "!@#$%^&*()_+=-|\\\"':;?/>.<,{}[]"
    for c in symbol_str:
        results = Info.objects.all().values('gender').annotate(mydefinedname=StringAgg('name',delimiter=c))
        try:
            for e in results:
                pass
        except IndexError:
            pass
        except Exception as err:
            print("[+] 报错信息: ", err)
            print("[+] 漏洞分隔符: ", c)
```

<div align=center><img src="./images/6.png"></div>

根据报错信息, 在`_execute`函数中打断点.

<div align=center><img src="./images/7.png"></div>

当遍历完数据库中的数据后, 进行`Fuzz`操作, 观察加入了`delimiter`为单引号取值的`sql`.

<div align=center><img src="./images/8.png"></div>

由于此时`sql`是个字符串, 因此会产生转义号, 该`sql`语句在`postgres`中的执行语句为:

```postgres
SELECT "vuln_app_info"."gender", STRING_AGG("vuln_app_info"."name", ''') AS "mydefinedname" FROM "vuln_app_info" GROUP BY "vuln_app_info"."gender"
```

接着尝试将`delimiter`设置为`')--`, 使得其注释掉后面的语句, 查看报错信息, 可以看到成功注释了`FROM`语句.

<div align=center><img src="./images/9.png"></div>

构造`exp`如下:

```python
-\') AS "demoname" FROM "vuln_app_info" GROUP BY "vuln_app_info"."gender" LIMIT 1 OFFSET 1 -- 
```

<div align=center><img src="./images/10.png"></div>


# CVE-2021-35042
## 漏洞简介
Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.

<div align=center><img src="./images/11.png"></div>

## 漏洞环境
 - 参考搭建好的环境[CVE-2021-35042](https://github.com/H3rmesk1t/Django-SQL-Inject-Env/tree/main/CVE-2021-35042).

## 漏洞分析
根据漏洞信息, 先跟进`order_by`函数, 该函数先调用了`clear_ordering`函数清除了`Query`类中的`self.order_by`参数, 接着调用`add_ordering`函数增加`self.order_by`参数.

<div align=center><img src="./images/12.png"></div>

通过`order_by`函数传入的参数为数组, 漏洞环境中接收参数的代码对应的`SQL`语句如下:

```python
query = request.GET.get('order_by', default='vuln')
res = User.objects.order_by(query)
```

```sql
SELECT "app_user"."vuln", "app_user"."order_by" FROM "app_user" ORDER BY "app_user"."order_by" ASC, "app_user"."vuln" ASC
```

跟进`add_ordering`函数, 函数对`ordering`做递归之后进行了判断, 如果`item`为字符串, 则继续进行如下五次判断:
 - `if '.' in item`: 判断是否为带列的查询, `SQL`语句中允许使用制定表名的列, 例如`order by (user.name)`, 即根据`user`表下的`name`字段进行排序. 该方法将在`Django 4.0`之后被删除, 因此判断成功之后通过`warning`警告, 之后进行`continue`.
 - `if item == '?'`: 当`item`的值为字符串`?`时, 则会设置`order by`的值为`RAND()`, 表示随机显示`SQL`语法的返回数据, 之后进行`continue`.
 - `if item.startswith('-')`: 当`item`开头为字符串`-`时, 则将`order by`查询的结果接上`DESC`, 表示降序排列, 默认的字符串则会接上`ASC`正序排列, 同时去除开头的`-`符号.
 - `if item in self.annotations`: 判断时候含有注释标识符, 有的话直接`continue`.
 - `if self.extra and item in self.extra`: 判断是否有额外添加，有的话直接`continue`.

经过五次判断之后, 进入到`self.names_to_path(item.split(LOOKUP_SEP), self.model._meta)`函数判断当前的`item`是否为有效的列名, 之后将所有的`ordering`传入到`Query`类中的`self.order_by`参数中进行后续处理.

<div align=center><img src="./images/13.png"></div>

在第一次判断中, `if '.' in item`进行判断能够确保`order by`查询能够更好地兼容何种形式的带列的查询, 但是判断是否为带表的查询之后, 如果判定为带表查询则进行`continue`, 而`continue`则直接跳过了`self.names_to_path`的对列的有效性检查. 跟进处理带字符串`.`的代码, 位于文件`django/db/models/sql/compiler.py`的`get_order_by`函数, 核心代码如下:

```python
if '.' in field:
    table, col = col.split('.', 1)
    order_by.append((
            OrderBy(
                RawSQL('%s.%s' % (self.quote_name_unless_alias(table), col), []),
                descending=descending
            ), False))
    continue
```

上述代码中, 函数`self.quote_name_unless_alias`处理表名, 同样使用字典来强制过滤有效的表名, 而后面的列面则恰好未经过过滤, 则可以构造闭合语句进行`SQL`注入.

参数`app_user.name) --`最终传入数据库的语句为:

```sql
SELECT `app_user`.`id`, `app_user`.`name` FROM `app_user` ORDER BY (`app_user`.name) --) ASC LIMIT 21
```

使用右括号`)`进行闭合之后进行堆叠注入, 基本的`payload`如下: `http://127.0.0.1:8000/vuln/?order_by=vuln_app_user.name);select%20updatexml(1,%20concat(0x7e,(select%20@@version)),1)%23`

<div align=center><img src="./images/14.png"></div>


# CVE-2022-28346
## 漏洞简介
An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a crafted dictionary (with dictionary expansion) as the passed **kwargs.

<div align=center><img src="./images/15.png"></div>

## 漏洞环境
 - 参考搭建好的环境[CVE-2022-28346](https://github.com/H3rmesk1t/Django-SQL-Inject-Env/tree/main/CVE-2022-28346).

## 漏洞分析
查找`Django`的`commit`记录, 在官方对的修复代码中可以看到测试用例.

<div align=center><img src="./images/16.png"></div>

由漏洞描述不, 跟进漏洞点`annotate`函数, 在`annotate`函数中首先会调用`_annotate`并传入`kwargs`.

<div align=center><img src="./images/17.png"></div>

`annotate`函数在完成对`kwargs.values()`合法性校验等一系列操作后, 将`kwargs`更新到`annotations`中, 随后遍历`annotations`中的元素调用`add_annotation`进行数据聚合.

<div align=center><img src="./images/18.png"></div>

跟进`add_annotation`函数, 继续调用`resolve_expression`解析表达式, 在此处并没有对传入的聚合参数进行相应的检查. 

<div align=center><img src="./images/19.png"></div>

继续跟进, 最终进入到`db.models.sql.query.py:resolve_ref`, `resolve_ref`会获取`annotations`中的元素, 并将其转换后带入到查询的条件中, 最后其结果通过`transform_function`聚合到一个`Col`对象中.

<div align=center><img src="./images/20.png"></div>

接着, 返回`db.models.query.py:_annotate`, 执行`sql`语句, 将结果返回到`QuerySet`中进行展示.

<div align=center><img src="./images/21.png"></div>

# 参考
 - [CVE-2020-7471 漏洞详细分析原理以及POC](https://xz.aliyun.com/t/7218#toc-3)
 - [Django CVE-2021-35042 order_by SQL注入分析](https://xz.aliyun.com/t/9834#toc-4)
 - [Django security releases issued: 4.0.4, 3.2.13, and 2.2.28](https://www.djangoproject.com/weblog/2022/apr/11/security-releases/)
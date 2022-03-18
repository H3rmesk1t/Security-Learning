# Java安全学习—OGNL表达式注入

Author: H3rmesk1t

Data: 2022.03.18

# OGNL 简介
[OGNL](https://commons.apache.org/proper/commons-ognl/) stands for Object-Graph Navigation Language; it is an expression language for getting and setting properties of Java objects, plus other extras such as list projection and selection and lambda expressions. You use the same expression for both getting and setting the value of a property.

The Ognl class contains convenience methods for evaluating OGNL expressions. You can do this in two stages, parsing an expression into an internal form and then using that internal form to either set or get the value of a property; or you can do it in a single stage, and get or set a property using the String form of the expression directly.

# OGNL 三要素
 - 表达式(Expression): 表达式是整个`OGNL`的核心内容, 所有的`OGNL`操作都是针对表达式解析后进行的. 通过表达式来告诉`OGNL`操作要干些什么. 因此, 表达式其实是一个带有语法含义的字符串, 整个字符串将规定操作的类型和内容. `OGNL`表达式支持大量的表达式, 如"链式访问对象"、表达式计算、甚至还支持`Lambda`表达式.
 - `Root`对象: `OGNL`的`Root`对象可以理解为`OGNL`的操作对象. 当指定了一个表达式的时候, 需要指定这个表达式针对的是哪个具体的对象. 而这个具体的对象就是`Root`对象, 这就意味着, 如果有一个`OGNL`表达式, 则需要针对`Root`对象来进行`OGNL`表达式的计算并且返回结果.
 - 上下文环境: 有个`Root`对象和表达式, 就可以使用`OGNL`进行简单的操作了, 如对`Root`对象的赋值与取值操作. 但是, 实际上在`OGNL`的内部, 所有的操作都会在一个特定的数据环境中运行. 这个数据环境就是上下文环境(Context). `OGNL`的上下文环境是一个`Map`结构, 称之为`OgnlContext`. `Root`对象也会被添加到上下文环境当中去, 简而言之, 上下文就是一个`MAP`结构, 它实现了`java.utils.Map`的接口.

在`Struct2`中`ActionContex`即`OGNL`的`Context`, 其中包含的`ValueStack`即为`OGNL`的`Root`.

## ActionContext
`ActionContext`是上下文对象, 对应`OGNL`的`Context`, 是一个以`MAP`为结构、利用键值对关系来描述对象中的属性以及值的对象, 简单来说可以理解为一个`action`的小型数据库, 整个`action`生命周期(线程)中所使用的数据都在这个`ActionContext`中.

<div align=center><img src="./images/1.png"></div>

除了三个常见的作用域`request`、`session`、`application`外, 还有以下三个作用域:
 - `attr`: 保存着上面三个作用域的所有属性, 如果有重复的则以`request`域中的属性为基准;
 - `paramters`: 保存的是表单提交的参数;
 - `VALUE_STACK`: 值栈, 保存着`valueStack`对象, 也就是说可以通过`ActionContext`访问到`valueStack`中的值.

## ValueStack
值栈(ValueStack)就是`OGNL`表达式存取数据的地方. 在一个值栈中封装了一次请求所需要的所有数据.

在使用`Struts2`的项目中, `Struts2`会为每个请求创建一个新的值栈, 也就是说, 值栈和请求是一一对应的关系, 这种一一对应的关系使值栈能够线程安全地为每个请求提供公共的数据存取服务.

值栈可以作为一个数据中转站在前台与后台之间传递数据, 最常见的就是将`Struts2`的标签与`OGNL`表达式结合使用. 值栈实际上是一个接口, 在`Struts2`中利用`OGNL`时, 实际上使用的就是实现了该接口的`OgnlValueStack`类, 这个类是`OGNL`的基础. 值栈贯穿整个`Action`的生命周期, 每个`Action`类的对象实例都拥有一个`ValueStack`对象, 在`ValueStack`对象中保存了当前`Action`对象和其他相关对象. 要获取值栈中存储的数据, 首先应该获取值栈, 值栈的获取有两种方式.

### 在 request 中获取值栈
`ValueStack`对象在`request`范围内的存储方式为`request.setAttribute("struts.valueStack",valuestack)`, 可以通过如下方式从`request`中取出值栈的信息:

```java
//获取 ValueStack 对象，通过 request 对象获取
ValueStack valueStack = (ValueStack)ServletActionContext.getRequest().getAttribute(ServletActionContext.STRUTS_VALUESTACK_KEY);
```

### 在 ActionContext 中获取值栈
在使用`Struts2`框架时, 可以使用`OGNL`操作`Context`对象从`ValueStack`中存取数据, 也就是说, 可以从`Context`对象中获取`ValueStack`对象. 实际上, `Struts2`框架中的`Context`对象就是`ActionContext`.

`ActionContext`获取`ValueStack`对象的方式如下所示:

```java
// 通过 ActionContext 获取 valueStack 对象.
ValueStack valueStack = ActionContext.getContext().getValueStack();
```

`ActionContext`对象是在`StrutsPrepareAndExcuteFilter#doFilter`方法中被创建的, 在源码中用于创建`ActionContext`对象的`createActionContext`方法内可以找到获取的`ValueStack`对象的信息. 方法中还有这样一段代码: 

```java
ctx = new ActionContext(stack.getContext());
```

从上述代码中可以看出, `ValueStack`对象中的`Context`对象被作为参数传递给了`ActionContext`对象, 这也就说明`ActionContext`对象中持有了`ValueStack`对象的引用, 因此可以通过`ActionContext`对象获取`ValueStack`对象.

# OGNL 基本语法









# 参考
 - [OGNL表达式注入漏洞总结](https://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/)
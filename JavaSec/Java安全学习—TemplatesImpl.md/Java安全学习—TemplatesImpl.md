# Java安全学习—TemplatesImpl

Author: H3rmesk1t

Data: 2021.11.26

# ClassLoader

## 作用
> `ClassLoader`是用来加载`Class`的，它负责将`Class`的字节码形式转换成内存形式的`Class`对象，字节码可以来自于磁盘文件`*.class`，也可以是`jar`包里的`*.class`，也可以来自远程服务器提供的字节流，字节码的本质就是一个字节数组`[]byte`，有特定的复杂的内部格式
> 每个`Class`对象的内部都有一个`classLoader`字段来标识自己是由哪个`ClassLoader`加载的，`ClassLoader`就像一个容器，装载了很多已经加载的`Class`对象

```java
class Class<T> {
  ...
  private final ClassLoader classLoader;
  ...
}
```

## 延迟加载
> `JVM`运行并不是一次性加载所需要的全部类的，而是按需加载（延迟加载），程序在运行的过程中会逐渐遇到很多不认识的新类，这时候就会调用`ClassLoader`来加载这些类，加载完成后就会将`Class`对象存在`ClassLoader`里面，这样在下一次遇见时就不需要重新加载了

## 多样性
> 在`JVM`运行实例中会存在多个`ClassLoader`，不同的`ClassLoader`会从不同的地方加载字节码文件，它可以从不同的文件目录加载，也可以从不同的`jar`文件中加载，也可以从网络上不同的服务地址来加载

> 在`JVM`中，内置了三个重要的`ClassLoader`，分别是：`BootstrapClassLoader`、`ExtensionClassLoader`和`AppClassLoader`

```
[1] BootstrapClassLoader 负责加载 JVM 运行时核心类，这些类位于 JAVA_HOME/lib/rt.jar 文件中，常用内置库 java.xxx.* 都在里面，比如 java.util.*、java.io.*、java.nio.*、java.lang.* 等，这个 ClassLoader 比较特殊，它是由 C 代码实现的，因此也将它称之为「根加载器」

[2] ExtensionClassLoader 负责加载 JVM 扩展类，比如 swing 系列、内置的 js 引擎、xml 解析器 等，这些库名通常以 javax 开头，它们的 jar 包位于 JAVA_HOME/lib/ext/*.jar 中，有很多 jar 包

[3] AppClassLoader 才是直接面向用户的加载器，它会加载 Classpath 环境变量里定义的路径中的 jar 包和目录，自己编写的代码以及使用的第三方 jar 包通常都是由它来加载的
```

> 位于网络上静态文件服务器提供的`jar`包和`class`文件，`JDK`内置了一个`URLClassLoader`，用户只需要传递规范的网络路径给构造器就可以使用`URLClassLoader`来加载远程类库，`URLClassLoader`不但可以加载远程类库，还可以加载本地路径的类库，取决于构造器中不同的地址形式，`ExtensionClassLoader`和`AppClassLoader`都是`URLClassLoader`的子类，它们都是从本地文件系统里加载类库

## 传递性
> 当程序在运行过程中遇到了一个未知的类时，虚拟机的策略是使用调用者`Class`对象的`ClassLoader`来加载当前未知的类
> 调用者：在遇到这个未知的类时，虚拟机正在运行一个方法调用（静态方法或者实例方法），这个方法挂在哪个类上面，那这个类就是调用者`Class`对象
> 因为`ClassLoader`的传递性，所有延迟加载的类都会由初始调用`main`方法的这个`ClassLoader`全全负责，它就是`AppClassLoader`

## 双亲委派
> 由于`AppClassLoader`只负责加载`Classpath`下的类库，因此当`AppClassLoader`遇到没有加载的系统类库时，会将系统类库的加载工作交给`BootstrapClassLoader`和`ExtensionClassLoader`，这就是双亲委派

<img src="./images/1.png" alt="">

> 如上图所示，`AppClassLoader`在加载一个未知的类名时，并不是立即去搜寻`Classpath`，它会首先将这个类名称交给`ExtensionClassLoader`来加载，如果`ExtensionClassLoader`可以加载，那么`AppClassLoader`就不会进行加载，否则的话`AppClassLoader`会搜索`Classpath`；而`ExtensionClassLoader`在加载一个未知的类名时，也并不是立即搜寻`ext`路径，它会首先将类名称交给`BootstrapClassLoader`来加载，如果`BootstrapClassLoader`可以加载，`ExtensionClassLoader`也不会对其进行加载，否则的话才会搜索`ext`路径下的`jar`包

> `AppClassLoader`、`ExtensionClassLoader`、`BootstrapClassLoader`三者之间形成了一个级联的父子关系，优先把任务交给其父亲，当其父亲无法完成任务时才会轮到自己，在每个`ClassLoader`对象的内部都会存在一个`parent`属性指向自己的父加载器
> 这里还需要注意的一点是，在上一张图中的`ExtensionClassLoader`的`parent`指针是画的虚线，这是因为它的`parent`的值是`null`，当`parent`字段是`null`时，表示它的父加载器是「根加载器」，当`Class`对象的`classLoader`属性值是`null`时，就表示这个类也是「根加载器」加载的

> 双亲委派规则可能会变成三亲委派，四亲委派，这取决于使用的父加载器是谁，它会一直递归委派到根加载器

```java
class ClassLoader {
  ...
  private final ClassLoader parent;
  ...
}
```

## 自定义加载器
> 在`ClassLoader`里面有三个重要的方法: `loadClass()`、`findClass()`和`defineClass()`
> `loadClass()`方法是加载目标类的入口，它首先会查找当前`ClassLoader`以及它的双亲里面是否已经加载了目标类，如果没有找到就会让双亲尝试加载，当双亲都无法进行加载时，会调用`findClass()`让自定义加载器自己来加载目标类，`ClassLoader`的`findClass()`方法是需要子类来覆盖的，不同的加载器将使用不同的逻辑来获取目标类的字节码，拿到这个字节码之后再调用`defineClass()`方法将字节码转换成`Class`对象

> `Class.forName`和`ClassLoader.loadClass`都可以用来加载目标类，但是它们之间有一个小小的区别，那就是`Class.forName()`方法可以获取原生类型的`Class`，而`ClassLoader.loadClass()`则会报错

> 自定义加载器实现过程伪代码

```java
class ClassLoader {

  // 加载入口，定义了双亲委派规则
  Class loadClass(String name) {
    // 是否已经加载了
    Class t = this.findFromLoaded(name);
    if(t == null) {
      // 交给双亲
      t = this.parent.loadClass(name)
    }
    if(t == null) {
      // 双亲都不行，只能靠自己了
      t = this.findClass(name);
    }
    return t;
  }

  // 交给子类自己去实现
  Class findClass(String name) {
    throw ClassNotFoundException();
  }

  // 组装Class对象
  Class defineClass(byte[] code, String name) {
    return buildClassFromCode(code, name);
  }
}

class CustomClassLoader extends ClassLoader {

  Class findClass(String name) {
    // 寻找字节码
    byte[] code = findCodeFromSomewhere(name);
    // 组装Class对象
    return this.defineClass(code, name);
  }
}
```

# ClassLoader 加载字节码
> 在前面对`ClassLoader`的分析中，可以知道`ClassLoader`是用来加载字节码文件最基础的方法，且字节码在`ClassLoader`中的处理流程为：`loadClass()` -> `findClass()` -> `defineClass()`，因此在`java`中，字节码转换成`java`类最终发生在`defineClass()`方法中，但是该方法是一个`protected`属性的方法，只能通过反射来调用其，在现实情况下利用难度大，需要找到一个更简易使用的方法

<img src="./images/2.png" alt="">

# TemplatesImpl 加载字节码
> 在前面提到了`ClassLoader#defineClass`只能通过反射来进行调用，需要找一个更简易使用的方法，而在`TemplatesImpl`类中存在一个`TransletClassLoader`内部类重写了`defineClass()`方法

<img src="./images/3.png" alt="">

> 由于没有指明其定义域，而`Java`中默认情况下，如果一个方法没有显式声明作用域，其作用域为`default`，因此这里的`defineClass`由其父类的`protected`类型变成了一个`default`类型的方法，可以被类外部调用
> 这里又有一个问题了，那就是`TransletClassLoader`是一个内部类，只能被`TemplatesImpl`类中的方法调用，需要找到有哪些可用的方法和`TransletClassLoader`联系起来的

> 跟进后发现只有`defineTransletClasses`这一个方法是用到了`TransletClassLoader`的，由于`TemplatesImpl#defineTransletClasses`是`private`类型，因此需要继续跟进一下看看哪里调用了该方法

<img src="./images/4.png" alt="">

> 跟进`com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl.java`中，发现有三处调用了该方法

<img src="./images/5.png" alt="">

```java
private synchronized Class[] getTransletClasses()
public synchronized int getTransletIndex()
private Translet getTransletInstance()
```

> 接着上面的三个利用点进一步分析，`getTransletIndex()`方法可以直接作为一个触发的点（进过测试后并没有成功触发），而`getTransletClasses()`方法在`TemplatesImpl`类中已经没有继续被调用了，因此只剩下`getTransletInstance()`，跟进发现`public synchronized Transformer newTransformer()`调用了它，因此这里也可以作为一个触发点，继续跟下去发现`public synchronized Properties getOutputProperties()`调用了`newTransformer()`方法，因此这里也可以作为一个触发点

> 总结一下前面得到的两条调用链

```java
[1] TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses()->TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()  

[2] TemplatesImpl#getOutputProperties() ->TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses()->TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass() 
```
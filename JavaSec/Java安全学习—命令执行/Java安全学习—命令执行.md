# Java安全学习—命令执行

Author: H3rmesk1t

# Relation

`Java`中执行命令的方法主要有`java.lang.Runtime#exec()`，`java.lang.ProcessBuilder#start()`以及`java.lang.ProcessImpl#start()`，它们之间的调用关系如下图所示。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=NjcyYTZiZTQ1ZmQ4NTFmZGViMmMzMGI2NmMzYWQ0NmNfZXVuM0hBWjFQdHJEZkxYMVF2UnhtYWhTeWFsQzBEWGZfVG9rZW46Ym94Y25KTWQ2aVV2QTBkRWcxRWp0ZGtsVUxiXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

# Runtime

`Java`中最为常见命令执行方式就是使用`java.lang.Runtime#exec`方法来执行本地系统命令。

```Java
package com.security;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;

public class RuntimeExecDemo {

    public static void main(String[] args) throws Exception {

        InputStream inputStream = Runtime.getRuntime().exec("whoami").getInputStream();
        System.out.println(IOUtils.toString(inputStream, "gbk"));
    }
}
```

在某些时刻由于一些特殊的原因可能不能出现`Runtime`相关的关键词，此时可以采用反射的形式进行实现。

```Java
package com.security.CommandExecution;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Arrays;

public class RuntimeReflectDemo {

    public static void main(String[] args) throws Exception {

        String className = "java.lang.Runtime";
        byte[] classNameBytes = className.getBytes(); // [106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101]
        System.out.println(Arrays.toString(classNameBytes));

        String methodName = "getRuntime";
        byte[] methodNameBytes = methodName.getBytes(); // [103, 101, 116, 82, 117, 110, 116, 105, 109, 101]
        System.out.println(Arrays.toString(methodNameBytes));

        String methodName2 = "exec";
        byte[] methodNameBytes2 = methodName2.getBytes(); // [101, 120, 101, 99]
        System.out.println(Arrays.toString(methodNameBytes2));

        String methodName3 = "getInputStream";
        byte[] methodNameBytes3 = methodName3.getBytes(); // [103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109]
        System.out.println(Arrays.toString(methodNameBytes3));

        String payload = "whoami";
        // 反射java.lang.Runtime类获取class对象
        Class<?> clazz = Class.forName(new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101}));
        // 反射获取Runtime类的getRuntime方法
        Method method1 = clazz.getMethod(new String(new byte[]{103, 101, 116, 82, 117, 110, 116, 105, 109, 101}));
        // 反射获取Runtime类的exec方法
        Method method2 = clazz.getMethod(new String(new byte[]{101, 120, 101, 99}), String.class);
        // 反射调用Runtime.getRuntime().exec()方法
        Object obj = method2.invoke(method1.invoke(null, new Object[]{}), new Object[]{payload});
        // 反射获取Process类的getInputStream方法
        Method method3 = obj.getClass().getMethod(new String(new byte[]{103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109}));
        method3.setAccessible(true);

        InputStream inputStream = (InputStream) method3.invoke(obj, new Object[]{});
        System.out.println(IOUtils.toString(inputStream, "gbk"));

    }
}
```

`Windows`下`Runtime.exec()`方法调用链大致如下，可以看到和上文中提到的调用关系链相符：

```Java
<init>:320, ProcessImpl (java.lang)
start:137, ProcessImpl (java.lang)
start:1029, ProcessBuilder (java.lang)
exec:620, Runtime (java.lang)
exec:450, Runtime (java.lang)
exec:347, Runtime (java.lang)
main:11, RuntimeDemo (com.security.CommandExecution)
```

# ProcessBuilder

`ProcessBuilder`类用于创建操作系统进程。每个`ProcessBuilder`实例管理一个进程属性集，其`start`方法利用这些属性来创建进程。由于`java.lang.Runtime#exec()`后续会调用到`java.lang.ProcessBuilder#start()`，并且`ProcessBuilder#start()`是`public`类型的，因此也可以直接利用其来执行命令。

```Java
package com.security.CommandExecution;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;

public class ProcessBuilderDemo {

    public static void main(String[] args) {

        try {
            InputStream inputStream = new ProcessBuilder("ipconfig", "/all").start().getInputStream();
            System.out.println(IOUtils.toString(inputStream, "gbk"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

# ProcessImpl

对于`java.lang.ProcessImpl`类并不能直接调用，但是可以通过反射来间接调用`ProcessImple#start()`来达到命令执行的目的。

```Java
package com.security.CommandExecution;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Map;

public class ProcessImplDemo {

    public static void main(String[] args) {

        try {
            String[] exp = {"cmd", "/c", "ipconfig", "/all"};
            Class<?> clazz = Class.forName("java.lang.ProcessImpl");
            Method method = clazz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
            method.setAccessible(true);

            InputStream inputStream = ((Process) method.invoke(null, exp, null, ".", null, true)).getInputStream();
            System.out.println(IOUtils.toString(inputStream, "gbk"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

# ScriptEngine

`javax.script.ScriptEngine`类是`Java`自带的用于解析并执行`JS`代码。`ScriptEngine`接口中有一个`eval`方法，可以执行`Java`代码。但需要注意的是，需要在有相应`engine`的环境中才能有效。

```Java
package com.security.CommandExecution;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

public class ScriptEngineDemo {

    public static void main(String[] args) throws ScriptException {

        String exp = "function demo() {return java.lang.Runtime};d=demo();d.getRuntime().exec(\"calc\")";
        // String exp = "var test=Java.type(\"java.lang.Runtime\"); print(test.getRuntime().exec(\"calc\"))";
        // String exp = "var CollectionsAndFiles = new JavaImporter(java.lang);with (CollectionsAndFiles){var x= Runtime.getRuntime().exec(\"calc\")}";
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("js");
        engine.eval(exp);
    }
}
```

# JShell

从`Java 9`开始提供了一个叫`jshell`的功能，`jshell`是一个`REPL(Read-Eval-Print Loop)`命令行工具，提供了一个交互式命令行界面，在`jshell`中我们不再需要编写类也可以执行Java代码片段，开发者可以像`python`和`php`一样在命令行下愉快的写测试代码了。

```Java
package com.security.CommandExecution;

import jdk.jshell.JShell;

public class JShellDemo {

    public static void main(String[] args) {

        try {
            JShell.builder().build().eval(new String(Runtime.getRuntime().exec("calc").getInputStream().readAllBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

# Others

## Windows

在`Windows`中，当要进行写文件等操作时，命令前缀要加`cmd ``/``c`。在下图中示例代码执行`echo "h3rmesk1t" > 1.txt`时，可以看到是无法执行成功的。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTU5M2VkYjQwYmIxMmMyNjEwZGFlMWFiNDgyYWIxZWRfdHhacFlURUllWTFCOWRxTjE4Z2VUaGUwd2dXNmFKWHJfVG9rZW46Ym94Y252QzEydjVDU2pSSHYxOWFXaFNrUXBiXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

下断点跟进，先进入`java.lang.Runtime#exec(String command)`。

```Java
public Process exec(String command) throws IOException {
    return exec(command, null, null);
}
```

继续跟进，进入`java.lang.Runtime#exec(String command, String[] envp, File dir)`。这里先会判断传入的`command`是否为空，当不为空时会传入`StringTokenizer`类中。

```Java
public Process exec(String command, String[] envp, File dir)
    throws IOException {
    if (command.length() == 0)
        throw new IllegalArgumentException("Empty command");

    StringTokenizer st = new StringTokenizer(command);
    String[] cmdarray = new String[st.countTokens()];
    for (int i = 0; st.hasMoreTokens(); i++)
        cmdarray[i] = st.nextToken();
    return exec(cmdarray, envp, dir);
}
```

跟进`StringTokenizer`类，这里会将传入的字符串按照`\t\n\r\f`和空格进行分割。

```Java
public StringTokenizer(String str) {
    this(str, " \t\n\r\f", false);
}
```

可以看到再进一步调用`java.lang.Runtime#exec(String[] cmdarray, String[] envp, File dir)`前，传入的待执行命令字符串变成了`["echo", ""h3rmesk1t"", ">", "C:\Users\95235\Downloads\1.txt"]`。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=MjdhYmQzOTE4OTdmM2NlYWI0YTQxNzVjNzRmYmYyN2VfUUxhWTM4ampaM0dvZUdwVExUQzFKb1VzTVQ4eDhSWHhfVG9rZW46Ym94Y25HZFNlbHF4TGhDRHpvZ0hhN3ZPSUxjXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

之后再传入`ProcessBuilder`，最后来到`ProcessImpl`，`Runtime`和`ProcessBuilder`的底层实际上都是`ProcessImpl`。而不能执行`echo`命令的原因是因为`Java`找不到这个东西，没有环境变量，因此加上`cmd /c`即可。

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDhhZmY5ODJlZDc1NGU5YTBlMDcxM2UzZTgwMzgzZjhfVmZaUHhPM2NvSmJSQWN6OEZwNVowaEdOWWt3NVpSU1dfVG9rZW46Ym94Y255NGt5VHVkaXBOcjN2VHFxTHZnOHNlXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

## Linux

在`Linux`环境中也存在着类似的问题，例如`/bin/sh -c echo 1 > 1.txt`虽然会创建文件，但是文件并没有内容，这是因为`/bin/sh -c`需要一个字符串作为参数来执行。而当后续为字符串时，根据上面分析的，经过`StringTokenizer`类后，整个命令变成了`{"/bin/sh","-c",""echo","1",">","1.txt""}`。

因此，在`Linux`环境下，可以采用数组或者`Base64`编码的形式来执行命令。

```Java
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "echo 1 > 1.txt"});

/bin/bash -c {echo,base64-encode-string}|{base64,-d}|{bash,-i}
```
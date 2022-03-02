# Java安全学习—XStream反序列化漏洞

Author: H3rmesk1t

Data: 2022.03.02

# XStream
## 简介
[XStream](https://zh.wikipedia.org/wiki/XStream)是`Java`类库, 用来将对象序列化成`XML`格式, 或者将`XML`反序列化为对象.

## 序列化与反序列化
先定义一个接口类`DemoInterface`:

```java
package org.h3rmesk1t.XStream;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/2 11:25 上午
 */
public interface DemoInterface {

    void output();
}

```

接着定义`Demo`类来实现前面的接口:

```java
package org.h3rmesk1t.XStream;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/2 11:25 上午
 */
public class Demo implements DemoInterface {

    String name;

    public void output() {

        System.out.println("Hello, " + this.name);
    }
}
```

调用`XStream.toXML`来实现序列化, 调用`XStream.fromXML`来实现反序列化:

```java
package org.h3rmesk1t.XStream;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/2 11:27 上午
 */
public class DemoXML {

    public static void main(String[] args) throws FileNotFoundException {

//        Demo demo = new Demo();
//        demo.name = "h3rmesk1t";
//        XStream xStream = new XStream(new DomDriver());
//        String xml = xStream.toXML(demo);
//        System.out.println(xml);
        FileInputStream xml = new FileInputStream("/Users/h3rmesk1t/Desktop/JavaSec-Learn/src/main/java/org/h3rmesk1t/XStream/demo.xml");
        XStream xStream = new XStream(new DomDriver());
        Demo demo = (Demo) xStream.fromXML(xml);
        demo.output();
    }
}
```

序列化和反序列化操作分别输出:
 - 序列化

```xml
<org.h3rmesk1t.XStream.Demo>
    <name>h3rmesk1t</name>
</org.h3rmesk1t.XStream.Demo>
```

```text
Hello, h3rmesk1t
```
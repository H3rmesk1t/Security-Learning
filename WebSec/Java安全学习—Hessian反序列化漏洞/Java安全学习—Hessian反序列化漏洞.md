# Java安全学习—Hessian反序列化漏洞

Author: H3rmesk1t

Data: 2022.03.11

# 前言
本文先对`Hessian`反序列化漏洞进行学习, 为后续学习`Dubbo`相关的反序列化漏洞提供前置知识.

# 序列化/反序列化机制
这里补充一下在`Java`中, 序列化/反序列化机制大体分为以下两种, 参考[marshalsec.pdf](https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true).

## 基于Bean属性访问机制
 - SnakeYAML
 - jYAML
 - YamlBeans
 - Apache Flex BlazeDS
 - Red5 IO AMF
 - Jackson
 - Castor
 - Java XMLDecoder
 - ...

它们有共同点, 也有自己独有的不同处理方式. 最基本的区别是如何在对象上设置属性值, 有的通过反射自动调用`getter(xxx)`和`setter(xxx)`访问对象属性; 有的还需要调用默认`Constructor`; 有的处理器在反序列化对象时, 如果类对象的某些方法还满足自己设定的某些要求, 也会被自动调用; 还有`XMLDecoder`这种能调用对象任意方法的处理器; 有的处理器在支持多态特性时, 例如某个对象的某个属性是`Object`、`Interface`、`abstruct`等类型, 为了在反序列化时能完整恢复, 需要写入具体的类型信息, 这时候可以指定更多的类, 在反序列化时也会自动调用具体类对象的某些方法来设置这些对象的属性值. 这种机制的攻击面比基于`Field`机制的攻击面大, 因为它们自动调用的方法以及在支持多态特性时自动调用方法比基于`Field`机制要多.

## 基于Field机制
 - Java Serialization
 - Kryo
 - Hessian
 - json-io
 - XStream
 - ...

基于`Field`机制是通过特殊的`native`(`native`方法不是`java`代码实现的, 所以不会像`Bean`机制那样调用`getter`、`setter`等更多的`java`方法)方法或反射(最后也是使用了`native`方式)直接对`Field`进行赋值操作的机制, 不是通过`getter`、`setter`方式对属性赋值, 上面某些处理器如果进行了特殊指定或配置也可支持`Bean`机制方式.

# Hessian 简介
`Hessian`是二进制的`web service`协议, 官方对`Java`、`Flash`/`Flex`、`Python`、`C++`、`.NET C#`等多种语言都进行了实现, 是一个轻量级的`RPC`框架, 使用简单的方法提供了`RMI`的功能. `Hessian`基于`HTTP`协议进行传输, 采用二进制`RPC`协议, 适合于发送二进制数据, 对数据包比较大的情况比较友好.

## 区别测试
下面做个简单测试下`Hessian Serialization`与`Java Serialization`:

 - Demo.java

```java
package org.h3rmesk1t.Hessian;

import java.io.Serializable;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/11 11:39 上午
 */
public class Demo implements Serializable {

    private int age;
    private String name;


    public int getAge() {
        System.out.println("getAge call");
        return age;
    }

    public void setAge(int age) {
        System.out.println("setAge call");
        this.age = age;
    }

    public String getName() {
        System.out.println("getName call");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName call");
        this.name = name;
    }

    public Demo() {
        System.out.println("Demo default constractor call");
    }

    public Demo(int age, String name) {
        this.age = age;
        this.name = name;
    }

    @Override
    public String toString() {
        return "My name is " + name + " and my age is " + age;
    }
}
```

 - HJSerialization.java

```java
package org.h3rmesk1t.Hessian;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/11 11:38 上午
 */
public class HJessianSerialization {

    public static <T> byte[] hserialize(T t) {
        byte[] data = null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            HessianOutput hessianOutput = new HessianOutput(byteArrayOutputStream);
            hessianOutput.writeObject(t);
            data = byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }

    public static <T> T hdeserialize(byte[] date) {
        if (date == null) {
            return null;
        }
        Object obj = null;
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(date);
            HessianInput hessianInput = new HessianInput(byteArrayInputStream);
            obj = hessianInput.readObject();
            hessianInput.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) obj;
    }

    public static <T> byte[] jdkserialize(T t) {
        byte[] data = null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(t);
            objectOutputStream.close();
            data = byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }

    public static <T> T jdkdeserialize(byte[] date) {
        if (date == null) {
            return null;
        }
        Object obj = null;
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(date);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            obj = objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) obj;
    }

    public static void main(String[] args) throws Exception {
        Demo demo = new Demo(20, "h3rmesk1t");

        long htime1 = System.currentTimeMillis();
        byte[] hdata = hserialize(demo);
        long htime2 = System.currentTimeMillis();
        System.out.println("hessian serialize result length = " + hdata.length + "," + "cost time：" + (htime2 - htime1));

        long htime3 = System.currentTimeMillis();
        Demo hdemo = hdeserialize(hdata);
        long htime4 = System.currentTimeMillis();
        System.out.println("hessian deserialize result: " + hdemo + "," + "cost time：" + (htime4 - htime3) + "\n");

        long jdktime1 = System.currentTimeMillis();
        byte[] jdkdata = hserialize(demo);
        long jdktime2 = System.currentTimeMillis();
        System.out.println("jdk serialize result length = " + jdkdata.length + "," + "cost time：" + (jdktime2 - jdktime1));

        long jdktime3 = System.currentTimeMillis();
        Demo jdkdemo = hdeserialize(jdkdata);
        long jdktime4 = System.currentTimeMillis();
        System.out.println("jdk deserialize result: " + jdkdemo + "," + "cost time：" + (jdktime4 - jdktime3) + "\n");

    }
}
```

<div align=center><img src="./images/1.png"></div>

## Hessian概念图
`Hessian`序列化/反序列化机制的基本概念图如下:

<div align=center><img src="./images/2.png"></div>

 - AbstractSerializerFactory: 抽象序列化器工厂, 是管理和维护对应序列化/反序列化机制的工厂, 拥有 getSerializer 和 getDeserializer 方法, 默认的几种实现如下.
   - SerializerFactory: 标准的实现.
   - ExtSerializerFactory: 可以设置自定义的序列化机制, 通过该 Factory 可以进行扩展.
   - BeanSerializerFactory: 对 SerializerFactory 的默认 Object 的序列化机制进行强制指定, 指定为 BeanSerializer.
   - Serializer: 序列化的接口, 拥有 writeObject 方法.
   - Deserializer: 反序列化的接口, 拥有 readObject、resdMap、readList 方法.
   - AbstractHessianInput: Hessian 自定义的输入流, 提供对应的 read 各种类型的方法.
   - AbstractHessianOutput: Hessian 自定义的输出流，提供对应的 write 各种类型的方法.

`Hessian Serializer`/`Hessian Derializer`默认情况下实现了以下序列化/反序列化器, 用户也可通过接口/抽象类自定义序列化/反序列化器:

<div align=center><img src="./images/3.png"></div>

在`Hessian`的`Deserializer`中, 有以下几种默认实现的反序列化器:

<div align=center><img src="./images/4.png"></div>

# Hessian反序列化漏洞
和`Java`原生的序列化对比, `Hessian`更加高效并且非常适合二进制数据传输. 既然是一个序列化/反序列化框架, `Hessian`同样存在反序列化漏洞的问题.

对于`Hessian`反序列化漏洞的利用, 可以使用[marshalsec](https://github.com/mbechler/marshalsec)工具的`Gadget`而不是`ysoserial`的`Gadget`. 这是因为`ysoserial`是针对`Java`原生反序列化漏洞的, 并没有一些如`Hessian`等非`Java`原生反序列化漏洞的`Gadgets`.

针对`Hessian`反序列化的攻击, 在`marshalsec`这个工具里, 已经有了`5`个可用的`Gadgets`. 分别是:
 - Rome
 - XBean
 - Resin
 - SpringPartiallyComparableAdvisorHolder
 - SpringAbstractBeanFactoryPointcutAdvisor



# 参考
 - [Hessian 反序列化及相关利用链](https://paper.seebug.org/1131/)
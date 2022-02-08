# Java安全学习—Javassist

作者: H3rmesk1t@D1no

## 定义

> `Java`字节码以二进制的形式存储在`.class`文件中，每一个`.class`文件包含一个`Java`类或接口，`Javaassist`就是一个用来处理`Java`字节码的类库，它可以在一个已经编译好的类中添加新的方法，或者是修改已有的方法，并且不需要对字节码方面有深入的了解，同时也可以去生成一个新的类对象，通过完全手动的方式

## 创建 class 文件
> 创建对象的类 Demo 代码

```java
package CommonsCollections2;

import javassist.*;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/26 3:09 下午
 */
public class JavassistCreateDemo {
    /**
     * 创建一个 Demo 对象
     */
    public static void main(String[] args) {
        try {
            createDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void createDemo() throws Exception {
        ClassPool classPool = ClassPool.getDefault();

        // 创建一个空类
        CtClass ctClass = classPool.makeClass("com.commons-collections.CommonsCollections2.javassist.Demo");
        // 增加一个字段名 way
        CtField ctField = new CtField(classPool.get("java.lang.String"), "way", ctClass);
        // 设置访问级别为 private
        ctField.setModifiers(Modifier.PRIVATE);
        // 设置初始信息
        ctClass.addField(ctField, CtField.Initializer.constant("Misc"));

        // 生成 getter、setter 方法
        ctClass.addMethod(CtNewMethod.setter("setWay", ctField));
        ctClass.addMethod(CtNewMethod.getter("getWay", ctField));

        // 设置无参构造函数
        CtConstructor ctConstructor = new CtConstructor(new CtClass[]{}, ctClass);
        ctConstructor.setBody("{way = \"Misc\";}");
        ctClass.addConstructor(ctConstructor);

        // 设置有参构造函数
        CtConstructor ctConstructor1 = new CtConstructor(new CtClass[]{classPool.get("java.lang.String")}, ctClass);
        ctConstructor1.setBody("{$0.way = $1;}");
        ctClass.addConstructor(ctConstructor1);

        // 创建 printWayName 方法
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "printWayName", new CtClass[]{}, ctClass);
        ctMethod.setModifiers(Modifier.PUBLIC);
        ctMethod.setBody("{System.out.println(way);}");
        ctClass.addMethod(ctMethod);

        // 编译构造内容
        ctClass.writeFile("/Users/h3rmesk1t/Desktop/commons-collections/src/main/java/CommonsCollections2");
    }
}
```
> 生成的 Demo.class 文件内容

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.commons-collections.CommonsCollections2.javassist;

public class Demo {
    private String way = "Misc";

    public void setWay(String var1) {
        this.way = var1;
    }

    public String getWay() {
        return this.way;
    }

    public Demo() {
        this.way = "Misc";
    }

    public Demo(String var1) {
        this.way = var1;
    }

    public void printWayName() {
        System.out.println(this.way);
    }
}
```
> 在`Javassist`中，类`Javaassit.CtClass`表示`class`文件，一个`CtClass`对象可以处理一个`class`文件，`ClassPool`是`CtClass`对象的容器，它按需读取类文件来构造`CtClass`对象，并且保存`CtClass`对象以便以后使用；需要注意的是`ClassPool`会在内存中维护所有被它创建过的`CtClass，当`CtClass`数量过多时会占用大量的内存，`API`中给出的解决方案是有意识的调用`CtClass`的`detach()`方法以释放内存

> ClassPool:
> 1. `getDefault`: 返回默认的`ClassPool`是单例模式的，一般通过该方法创建的`ClassPool`
> 2. `appendClassPath`，`insertClassPath`: 将一个`ClassPath`加到类搜索路径的末尾位置或插入到起始位置，通常通过该方法写入额外的类搜索路径，以解决多个类加载器环境中找不到类的问题
> 3. `toClass`: 将修改后的`CtClass`加载至当前线程的上下文类加载器中，`CtClass`的`toClass`方法是通过调用本方法实现，需要注意的是一旦调用该方法则无法继续修改已经被加载的`class`
> 4. `get`，`getCtClass`: 根据类路径名获取该类的`CtClass`对象用于后续的编辑

> CtClass:
> 1. `freeze`: 冻结一个类，使其不可修改
> 2. `isFrozen`: 判断一个类是否已被冻结
> 3. `prune`: 删除类不必要的属性，以减少内存占用，需要注意的是调用该方法后许多方法无法将无法正常使用
> 4. `defrost`: 解冻一个类，使其可以被修改，如果事先知道一个类会被`defrost`，则禁止调用`prune`方法
> 5. `detach`: 将该`class`从`ClassPool`中删除
> 6. `writeFile`: 根据`CtClass`生成`.class`文件
> 7. `toClass`: 通过类加载器加载该`CtClass`


> CtMethod:
> 1. `insertBefore`: 在方法的起始位置插入代码
> 2. `insterAfter`: 在方法的所有`return`语句前插入代码以确保语句能够被执行，除非遇到`exception`
> 3. `insertAt`: 在指定的位置插入代码
> 4. `setBody`: 将方法的内容设置为要写入的代码，当方法被`abstract`修饰时，该修饰符被移除
> 5. `make`: 创建一个新的方法

## 调用生成的类对象
### 反射调用

> 将写入文件部分代码换成如下代码
```java
Object demo = ctClass.toClass().getInterfaces();
Method setWay = demo.getClass().getMethod("setWay", String.class);
setWay.invoke(demo, "Web");
Method execute = demo.getClass().getMethod("printWayName");
execute.invoke(demo);
```

### 读取 .class 文件调用

```java
ClassPool classPoll = ClassPool.getDefault();
// 设置类路径
pool.appendClassPath("/Users/h3rmesk1t/Desktop/commons-collections/src/main/java/");
CtClass ctClass = classPoll.get("com.commons-collections.CommonsCollections2.javassist.Demo");
Object demo = ctClass.toClass().newInstance();
//  ...... 下面和通过反射的方式一样去使用
```

### 接口调用
> 新建一个`DemoI`接口类

```java
package CommonsCollections2;

public interface DemoI {
    void setWay(String name);
    String getWay();
    void printWayName();
}
```
> 实现部分
```java
ClassPool classPool = ClassPool.getDefault();
pool.appendClassPath("/Users/h3rmesk1t/Desktop/commons-collections/src/main/java/");

CtClass codeClassI = classPool.get("CommonsCollections2.PersonI");
CtClass ctClass = classPool.get("CommonsCollections2.Person");
ctClass.setInterfaces(new CtClass[]{codeClassI});

DemoI demo = (DemoI)ctClass.toClass().newInstance();
System.out.println(demo.getWay());
demo.setWay("xiaolv");
demo.printWay();
```

## 修改现有的类
> 一般会遇到的使用场景应该是修改已有的类，比如常见的日志切面，权限切面都是利用`javassist`来实现这个功能

> 例如如下类对象

```java
public class PersonService {

    public void getPerson(){
        System.out.println("get Person");
    }
    public void personFly(){
        System.out.println("oh my god,I can fly");
    }
}
```

> 实现修改部分代码

```java
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.Modifier;

import java.lang.reflect.Method;

public class UpdatePerson {

    public static void update() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.get("com.rickiyang.learn.javassist.PersonService");

        CtMethod personFly = cc.getDeclaredMethod("personFly");
        personFly.insertBefore("System.out.println(\"起飞之前准备降落伞\");");
        personFly.insertAfter("System.out.println(\"成功落地。。。。\");");


        //新增一个方法
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "joinFriend", new CtClass[]{}, cc);
        ctMethod.setModifiers(Modifier.PUBLIC);
        ctMethod.setBody("{System.out.println(\"i want to be your friend\");}");
        cc.addMethod(ctMethod);

        Object person = cc.toClass().newInstance();
        // 调用 personFly 方法
        Method personFlyMethod = person.getClass().getMethod("personFly");
        personFlyMethod.invoke(person);
        //调用 joinFriend 方法
        Method execute = person.getClass().getMethod("joinFriend");
        execute.invoke(person);
    }

    public static void main(String[] args) {
        try {
            update();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
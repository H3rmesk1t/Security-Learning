# Java安全学习—反射机制

Author: H3rmesk1t

# 定义
> Java 反射机制可以可以无视类方法、变量去访问权限修饰符（如：protected、private 等），并且可以调用任意类的任何方法、访问并修改成员变量值

# 反射的定义
> 反射是 Java 的特征之一，反射的存在使运行中的 Java 够获取自身信息，并且可以操作类或对象的内部属性
> 通过反射可以在运行时获得程序或程序集中每一个类型的成员和成员信息；Java 的反射机制亦是如此，在运行状态中，通过 Java 的反射机制，能够判断一个对象的任意方法和属性

# 反射的基本运用
## 获取类对象
### forName() 方法
> 当要使用 Class 类中的方法获取类对象时，就需要使用 forName() 方法，只需要有类名称即可，在配置 JDBC 中通常采用这种方法

<img src="./images/1.png" alt="">

### .class 方法
> 任何数据类型都具备静态的属性，因此可以使用 `.class` 直接获取其对应的 Class 对象，使用这种方法时需要明确用到类中的静态成员

<img src="./images/2.png" alt="">

### getClass() 方法
> 可以通过 Object 类中的 `getCLass()` 方法来获取字节码，使用这种方法时必须明确具体的类，然后创建对象

<img src="./images/3.png" alt="">

### getSystemClassLoad().loadClass() 方法
> `getSystemClassLoad().loadClass()` 方法与 `forName()` 方法类似，只要有类名即可；但是，`forName()` 的静态方法 JVM 会装载类，并且执行 `static()` 中的代码，而 `getSystemClassLoad().loadClass()` 不会执行 `ststic()` 中的代码
> 例如 JDBC 中就是利用 `forName()` 方法，使 JVM 查找并加载制定的类到内存中，此时将 `com.mysql.jdbc.Driver` 当作参数传入就是让 JVM 去 `com.mysql.jdbc` 路径下查找 `Driver` 类，并将其加载到内存中

<img src="./images/4.png" alt="">

## 获取类方法
> 获取某个 Class 对象的方法集合主要有以下几种方法

### getDeclaredMethods 方法
> 该方法返回类或接口声明的所有方法，包括 public、private 以及默认方法，但不包括继承的方法

<img src="./images/5.png" alt="">

### getMethods 方法
> getMethods 方法返回某个类的所有 public 方法，包括其继承类的 public 方法

<img src="./images/6.png" alt="">

### getMethod 方法
> getMethod 方法只能返回一个特定的方法，例如返回 Runtime 类中的 exec() 方法，该方法的第一个参数为方法名称，后面的参数为方法的参数对应 Class 的对象

<img src="./images/11.png" alt="">

### getDeclaredMethod 方法
> 该方法与 getMethod 方法类似，也只能返回一个特定的方法，该方法的第一个参数为方法名，第二个参数名是方法参数

<img src="./images/10.png" alt="">

## 获取类成员变量
> 先创建一个 Student 类
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

### getDeclaredFields 方法
> getDeclaredFields 方法能够获得类的成员变量数组包括 public、private 和 protected，但是不包括父类的声明字段

<img src="./images/7.png" alt="">

### getFields 方法
> getFields 方法能够获取某个类的所有 public 字段，包括父类中的字段

<img src="./images/8.png" alt="">

### getDeclaredField 方法
> 该方法与 getDeclaredFields 方法的区别是只能获得类的单个成员变量

<img src="./images/9.png" alt="">
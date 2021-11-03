# 前言
> 在之前粗略的了解了一下 Java 的反射机制，这里进一步总结一下 Java 安全中反射的知识点

# Java 反射机制定义
> Java反射机制是在运行状态中，对于任意一个类，都能够知道这个类中的所有属性和方法
> 对于任意一个对象，都能够调用它的任意一个方法和属性
> 这种动态获取的信息以及动态调用对象的方法的功能称为 Java 语言的反射机制

> 需要注意的是：Java 的反序列化问题都基于反射机制

# Java 反射机制功能
> 1. 在运行时判断任意一个对象所属的类
> 2. 在运行时构造任意一个类的对象
> 3. 在运行时判断任意一个类所具有的成员变量和方法
> 4. 在运行时调用任意一个方法
> 5. 生成动态代理

# Java 反射机制应用场景
> 1. 逆向代码
> 2. 与注解相结合的框架
> 3. 单纯的反射机制应用框架
> 4. 动态生成类框架

# 反射常见的几种使用方法
> 获取类：forName()
> 实例化类的对象：newInstance()
> 获取函数：getMethod()
> 执行函数：invoke()

# 获取 Class 对象的方法
```java
1、
Class demo1 = ReflectDemo.class;

2、
ReflectDemo reflectDemo = new ReflectDemo();
Class demo2 = reflectDemo.getClass();

3、
Class demo3 = Class.forName("reflectdemo.ReflectDemo");

4、
Class demo4 = ClassLoader.getSystemClassLoader().loadClass("reflectdemo.ReflectDemo");
```

# 获取成员变量 Field
```java
import java.lang.reflect.Field

Field[] getFields(): 获取所有 public 修饰的成员变量
Field[] getDeclaredFields(): 获取所有的成员变量，不考虑修饰符
Field getField(String name): 获取指定名称的 public 修饰的成员变量
Field getDeclaredField(String name): 获取指定的成员变量 
```

# 获取成员方法 Method
```java
//第一个参数获取该方法的名字，第二个参数获取标识该方法的参数类型
Method getMethod(String name, 类<?>... parameterTypes) //返回该类所声明的public方法
Method getDeclaredMethod(String name, 类<?>... parameterTypes) //返回该类所声明的所有方法

Method[] getMethods() //获取所有的public方法，包括类自身声明的public方法，父类中的public方法、实现的接口方法
Method[] getDeclaredMethods() // 获取该类中的所有方法
```

# 获取构造函数
```java
Constructor<?>[] getConstructors() ：只返回public构造函数
Constructor<?>[] getDeclaredConstructors() ：返回所有构造函数
Constructor<> getConstructor(类<?>... parameterTypes) : 匹配和参数配型相符的public构造函数
Constructor<> getDeclaredConstructor(类<?>... parameterTypes) ： 匹配和参数配型相符的构造函数
```

# 利用 Java 反射机制创建类对象
> 可以通过反射来生成实例化对象，一般使用 Class 对象的 `newInstance()` 方法来进行创建类对象，使用的方式只需要通过 `forName()` 方法获取到的 class 对象中进行 `newInstance()` 方法创建即可

```java
Class demo = Class.forName("com.reflect.MethodDemo");    //创建 Class 对象
Object test = demo.newInstance();
```

# 利用 Java 反射机制创建类并执行方法
```java
import java.lang.reflect.Method;

public class ReflectDemo {
    public void reflectMethod() {
        System.out.println("成功反射");
    }
    public static void main(String[] args) {
        try {
            Class demo = Class.forName("com.reflect.ReflectDemo");  //创建 Class 对象
            Object test = demo.newInstance();   //创建实例对象
            Method method = demo.getMethod("reflectMethod");    //创建 reflectMethod 方法
            method.invoke(test);    //调用实例对象方法
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
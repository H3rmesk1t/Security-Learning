# Java安全学习—MySQL JDBC反序列化漏洞

Author: H3rmesk1t

Data: 2022.03.21

# JDBC 简介
[Java Database Connectivity](https://en.wikipedia.org/wiki/Java_Database_Connectivity) (JDBC) is an application programming interface (API) for the programming language Java, which defines how a client may access a database. It is a Java-based data access technology used for Java database connectivity. It is part of the Java Standard Edition platform, from Oracle Corporation. It provides methods to query and update data in a database, and is oriented toward relational databases. A JDBC-to-ODBC bridge enables connections to any ODBC-accessible data source in the Java virtual machine (JVM) host environment.

```java
jdbc://driver://host:port/database?配置name1=配置Value1&配置name2=配置Value2
```

# 漏洞原理
当攻击者能够控制`JDBC`连接设置项, 那么就可以通过设置其指向恶意`MySQL`服务器进行`ObjectInputStream.readObject`的反序列化攻击从而`RCE`.

具体点说，就是通过JDBC连接MySQL服务端时，会有几个内置的SQL查询语句要执行，其中两个查询的结果集在MySQL客户端被处理时会调用ObjectInputStream.readObject()进行反序列化操作。如果攻击者搭建恶意MySQL服务器来控制这两个查询的结果集，并且攻击者可以控制JDBC连接设置项，那么就能触发MySQL JDBC客户端反序列化漏洞。

可被利用的两条查询语句：

SHOW SESSION STATUS
SHOW COLLATION

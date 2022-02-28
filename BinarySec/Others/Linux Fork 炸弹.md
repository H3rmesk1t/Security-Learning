# Linux Fork 炸弹

Author: H3rmesk1t

Data: 2022.02.24

# 原理分析
`Jaromil`在`2002`年设计了最为精简的一个`Linux Fork`炸弹, 虽然整个代码只有`13`个字符, 但是在`shell`中运行后几秒后系统就会宕机:

```shell
:() { :|:& };:
```

由于在一行中无法直观的理解这十三个字符构成的`Linux Fork`炸弹, 因此我们将其用换行的形式分解出来:

```shell
:()
{
    :|:&
};
:
```

```shell
Fork()
{
    Fork|Fork&
};
Fork
```

在上面的代码中, 因为`shell`中函数可以省略`function`关键字, 所以十三个字符是功能是定义一个函数与调用这个函数, 函数的名称为`:`, 主要的核心代码是`:|:&`, 这是一个函数本身的递归调用, 通过`&`实现在后台开启新进程运行, 通过管道实现进程呈几何形式增长, 最后再通过`:`来调用函数引爆炸弹. 因此几秒钟后, 系统就会因为处理不过来太多的进程而死机, 而解决的唯一办法就是重启.

# 实操演示
在云服务器中输入`shell`命令: `:(){ :|:& };:`, 可以看到不一会服务器就宕机了.

<div align=center><img src="./Linux Fork 炸弹/1.png"></div>

<div align=center><img src="./Linux Fork 炸弹/2.png"></div>

这里还可以用别的语言来创建一个`Fork`炸弹, 例如如下代码:

```python
import os

while True:
    os.fork()
```

<div align=center><img src="./Linux Fork 炸弹/4.png"></div>

# Linux Fork 炸弹危害
`Fork`炸弹带来的后果就是耗尽服务器资源, 使服务器不能正常的对外提供服务, 也就是常说的`DoS`攻击. 与传统`1v1`、通过不断向服务器发送请求造成服务器崩溃不同, `Fork`炸弹并不要付出什么就可以达到惊人的效果, 并且这个函数是不需要`root`权限就可以运行的.

# Linux Fork 炸弹预防
`Fork`炸弹的本质无非就是靠创建进程来抢占系统资源, 在`Linux`中, 我们可以通过`ulimit`命令来限制用户的某些行为, 运行`ulimit -a`可以查看我们能做哪些限制.

<div align=center><img src="./Linux Fork 炸弹/3.png"></div>

可以看到对于`-u`参数的话是可以设置`max user processes`的值的. 因此, 我们可以使用`ulimit -u 10`来允许用户最多创建`10`个进程, 利用这个手段来预防`Fork`炸弹. 但是这样的话也有一个缺陷, 当我们关闭终端后该命令就失效了, 因此我们需要将该设置写入配置文件. 可以通过修改`/etc/security/limits.conf`文件来进行更深层次的预防, 在文件里添加如下一行: `ubuntu(用户名) - nproc 10`. 这个时候我们再次运行炸弹就不会报内存不足了, 而是提示`-bash: fork: retry: No child processes`.
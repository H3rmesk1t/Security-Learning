# Chunk Extend and Overlapping
## 概述
- `chunk extend`是堆漏洞中一种常见的利用手法，通过`extend`可以实现`chunk overlapping`的效果，该利用手法需要满足以下的条件：
  - 程序中存在基于堆的漏洞
  - 漏洞可以控制`chunk header`中的数据

- `ptmalloc`通过`chunk header`的数据判断`chunk`的使用情况和对`chunk`的前后块进行定位，`chunk extend`就是通过控制`pre_size`字段和`size`字段来实现跨越块操作从而导致`overlapping`的
- 一般来说，这种技术并不能直接控制程序的执行流程，但是可以控制`chunk`中的内容，如果`chunk`存在字符串指针、函数指针等，就可以利用这些指针来进行信息泄漏和控制执行流程
- 此外通过`extend`可以实现`chunk overlapping`，通过`overlapping`可以控制`chunk`的`fd`指针和`bk`指针，从而可以实现`fastbin attack`等利用

## 漏洞原理
### 对inuse的fastbin进行extend
- 示例代码

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    void *ptr1, *ptr2;

    ptr1 = malloc(0x10); // 分配大小为0x10的chunk1
    ptr2 = malloc(0x10); // 分配大小为0x10的chunk2

    *(long long *)((long long)ptr1 - 0x8) = 0x41; // 修改chunk1的size字段

    free(ptr1); // 释放chunk1

    ptr1 = malloc(0x30); // 实现extend
    return 0;
}
```

- `malloc`两块大小为`0x10`的`chunk`后，堆分布如图所示

![](images/1.png#pic_center)

- 接着将`chunk1`的`size`字段值更改为`0x41`，`0x41`是因为`chunk`的`size`字段包含了用户控制的大小和`chunk header`的大小，在题目或实际应用中，这一步可以由堆溢出得到
- 接着执行`free`操作，此时可以看到`chunk1`和`chunk2`合并成一个`0x40`大小的`chunk`释放了

![](images/2.png#pic_center)

- 之后通过`malloc(0x30)`得到`chunk1+chunk2`的堆块，此时就可以直接控制`chunk2`中的内容，这种状态被称为`overlapping chunk`

![](images/3.png#pic_center)

### 对inuse的smallbin进行extend
- 示例代码

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    void *ptr, *ptr1;

    ptr=malloc(0x80);// 分配大小为 0x80 的chunk1
    malloc(0x10); //分配第二个 0x10 的 chunk2
    malloc(0x10); //防止与top chunk合并

    *(int *)((int)ptr - 0x8) = 0xb1;
    free(ptr);

    ptr1 = malloc(0xa0);
    return 0;
}
```

- 在上述示例代码中，因为分配的`size`不处于`fastbin`的范围，因此在释放时如果与`top chunk`相连会导致和`top chunk`合并，所以需要额外分配一个`chunk`，把释放的块与`top chunk`隔开
- `malloc`三块`chunk`后，堆分布如图所示

![](images/4.png#pic_center)

- 接着将`chunk1`的`size`字段值更改为`0xb1`

![](images/5.png#pic_center)

- 接着`free`掉`chunk1`，`chunk1`把`chunk2`的内容吞并掉并一起放入`unsorted bin`

![](images/6.png#pic_center)

- 当再次进行分配时，会取回`chunk1`和`chunk2`的空间，此时就可以控制`chunk2`中的内容

![](images/7.png#pic_center)

### 对free的smallbin进行extend
- 示例代码

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
    void *ptr, *ptr1;

    ptr = malloc(0x80); // 分配大小为0x80的 chunk1
    malloc(0x10);       // 分配大小为0x10的 chunk2

    free(ptr);          // 首先进行释放, 使得chunk1进入unsorted bin

    *(long long*)((long long)ptr - 0x8) = 0xb1;
    ptr1 = malloc(0xa0);
	
	return 0;
}
```

- 该利用方式下，先释放`chunk1`，然后再修改处于`unsorted bin`中的`chunk1`的`size`域
- `malloc`两块`chunk`后，堆分布如图所示

![](images/8.png#pic_center)

- 接着先`free`掉`chunk1`，让它进入`unsorted bin`

![](images/9.png#pic_center)

- 接着将`chunk1`的`size`字段值更改为`0xb1`

![](images/10.png#pic_center)


- 此时再进行`malloc`分配就可以得到`chunk1+chunk2`的堆块，从而控制了`chunk2`的内容

![](images/11.png#pic_center)

## 漏洞利用
- 通常情况下，`Chunk Extend/Shrink`技术并不能直接控制程序的执行流程，但是可以控制`chunk`中的内容
- 如果`chunk`存在字符串指针、函数指针等，就可以利用这些指针来进行信息泄漏和控制执行流程
- 此外通过`extend`可以实现`chunk overlapping`，通过`overlapping`可以控制`chunk`的`fd/bk`指针从而可以实现`fastbin attack`等利用

### 通过extend后向overlapping
- 示例代码

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    void *ptr, *ptr1;

    ptr = malloc(0x10);//分配第1个 0x80 的 chunk1
    malloc(0x10); //分配第2个 0x10 的 chunk2
    malloc(0x10); //分配第3个 0x10 的 chunk3
    malloc(0x10); //分配第4个 0x10 的 chunk4
	
    *(long long *)((long long)ptr - 0x8) = 0x61;
    free(ptr);
	
    ptr1 = malloc(0x50);
	return 0;
}
```

- `malloc(0x50)`对`extend`区域重新占位后，其中`0x10`的`fastbin`块依然可以正常的分配和释放，此时已经构成`overlapping`, 通过对`overlapping`进行操作可以实现`fastbin attack`

![](images/12.png#pic_center)

![](images/13.png#pic_center)

### 通过extend前向overlapping
- 示例代码

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
    void *ptr1, *ptr2, *ptr3, *ptr4;
    ptr1 = malloc(128);     // smallbin1
    ptr2 = malloc(0x10);    // fastbin1
    ptr3 = malloc(0x10);    // fastbin2
    ptr4 = malloc(128);     // smallbin2
    malloc(0x10);           // 防止与 top 合并
	
    free(ptr1);
    *(long long *)((long long)ptr4 - 0x8) = 0x90;   // 修改pre_inuse域
    *(long long *)((long long)ptr4 - 0x10) = 0xd0;  // 修改pre_size域
    free(ptr4);              // unlink进行前向extend
    malloc(0x150);           // 占位块

	return 0;
}
```

- 通过修改`pre_inuse`域和`pre_size`域实现合并前面的块
- 前向`extend`利用了`small bin`的`unlink`机制，通过修改`pre_size`域可以跨越多个`chunk`进行合并来实现`overlapping`

![](images/14.png#pic_center)

![](images/15.png#pic_center)
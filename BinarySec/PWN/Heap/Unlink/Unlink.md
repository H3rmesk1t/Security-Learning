# Unlink
## 概述
- 执行`free(chunk)`时：
  - `glibc`会先判断要释放的`chunk`的类型，如果是`small chunk`或者`large chunk`的话需要进行合并
  - 判断前向合并（低地址），如果前一个`chunk`处于空闲状态，则进行前向合并
  - 判断后向合并（高地址），如果后一个`chunk`处于空闲状态，则进行后向合并
  - 堆需要合并的`chunk`进行`unlink`操作

- `unlink`是`libc`中定义的一个宏，在`malloc.c`中找到`unlink`定义如下：

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                           
    FD = P->fd;								     
    BK = P->bk;								     
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		     
      malloc_printerr (check_action, "corrupted double-linked list", P, AV); 
    else {								     
        FD->bk = BK;							     
        BK->fd = FD;							     
        if (!in_smallbin_range (P->size)				     
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		     
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	     
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))   
	      malloc_printerr (check_action,				     
			       "corrupted double-linked list (not small)",   
			       P, AV);					     
            if (FD->fd_nextsize == NULL) {				     
                if (P->fd_nextsize == P)				     
                  FD->fd_nextsize = FD->bk_nextsize = FD;		     
                else {							     
                    FD->fd_nextsize = P->fd_nextsize;			     
                    FD->bk_nextsize = P->bk_nextsize;			     
                    P->fd_nextsize->bk_nextsize = FD;			     
                    P->bk_nextsize->fd_nextsize = FD;			     
                  }							     
              } else {							     
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		     
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		     
              }								     
          }								     
      }									     
}
```

- 在执行`free`函数时执行了`_int_free`函数，在`_int_free`函数中调用了`unlink`宏：

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    {
      errstr = "free(): invalid pointer";
    errout:
      if (!have_lock && locked)
        (void) mutex_unlock (&av->mutex);
      malloc_printerr (check_action, errstr, chunk2mem (p), av);
      return;
    }
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      errstr = "free(): invalid size";
      goto errout;
    }

  check_inuse_chunk(av, p);

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might have let to a false positive.  Redo the test
	   after getting the lock.  */
	if (have_lock
	    || ({ assert (locked == 0);
		  mutex_lock(&av->mutex);
		  locked = 1;
		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
	if (! have_lock)
	  {
	    (void)mutex_unlock(&av->mutex);
	    locked = 0;
	  }
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
	/* Check that the top of the bin is not the record we are going to add
	   (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
	  }
	/* Check that size of fastbin chunk at the top is the same as
	   size of the chunk that we are adding.  We can dereference OLD
	   only if we have the lock, otherwise it might have already been
	   deallocated.  See use of OLD_IDX below for the actual check.  */
	if (have_lock && old != NULL)
	  old_idx = fastbin_index(chunksize(old));
	p->fd = old2 = old;
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
	errstr = "invalid fastbin entry (free)";
	goto errout;
      }
  }

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto errout;
      }

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (normal)";
	goto errout;
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	{
	  errstr = "free(): corrupted unsorted chunks";
	  goto errout;
	}
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }

    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (have_fastchunks(av))
	malloc_consolidate(av);

      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av);
#endif
      } else {
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);
      }
    }

    if (! have_lock) {
      assert (locked);
      (void)mutex_unlock(&av->mutex);
    }
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}
```

## 漏洞原理


- 下面通过代码的调试来理解一下`unlink`的原理，示例代码中申请了`7`个`chunk`，接着依次释放`first_chunk`、`second_chunk`、`third_chunk`
- 释放这几个`chunk`是因为地址相邻的`chunk`释放之后会进行合并，地址不相邻的时候不会合并，由于申请的是`0x80`的`chunk`，所以在释放之后不会进入`fastbin`而是先进入`unsortbin`
- 由于环境是`glibc 2.31`的，因此这里用工具`glibc-all-in-one`下载需要的`glibc`版本，然后使用工具`patchelf`来更换程序的`glibc`：`patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-2.23.so --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.23-0ubuntu3_amd64 test`

```c
#include <stdio.h>
#include <stdlib.h>

void main()
{
	long *first_chunk = malloc(0x80);
	long *second_chunk = malloc(0x80);
	long *third_chunk = malloc(0x80);
	long *fouth_chunk = malloc(0x80);
	long *fifth_chunk = malloc(0x80);
	long *sixth_chunk = malloc(0x80);
	
	free(first_chunk);
	free(third_chunk);
	free(fouth_chunk);
	
	return 0;
}
```

- 利用`gdb`打开编译好的例子，因为使用了`-g`参数，所以在第`17`行使用命令`b 17`下断点，接下使用命令`r`来让程序跑起来，使用命令`bin`看一下双向链表中的排列结构，使用`heap`命令查看一下这几个被`free`的`chunk`

![](images/1.png#pic_center)

```
first_chunk_bk -> third_chunk
third_chunk_bk -> fifth_chunk
fifth_chunk_fd -> third_chunk
third_chunk_fd -> first_chunk
```

![](images/2.png#pic_center)

- `unlink`的目的与过程，其目的是把一个双向链表中的空闲块拿出来，例如`free`时和目前物理相邻的`free chunk`进行合并，利用`unlink`所造成的漏洞时，其实就是对`chunk`进行内存布局，然后借助`unlink`操作来达成修改指针的效果
- `unlink`的流程大致如下：
  - 首先根据`chunk P`的`fd`指针和`bk`指针确定`chunk P`在`bin`前后的`chunk`分别是`FD`和`BK`
  - 然后让`chunk FD`的`bk`指针指向`chunk BK`
  - 最后让`chunk BK`的`fd`指针指向`chunk FD`


![](images/3.png#pic_center)




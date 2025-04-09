---
title: 多线程：Python VS Golang
date: 2025-03-30 13:34:00
tags: [Python, Golang]
categories: 学习
---

Golang 的牛皮之处
<!--more-->

## 前言

平时做密码题经常会用到并行计算加速爆破，但是一直没仔细研究过这方面的东西。

## Python 的多线程

### Review: multiprocessing VS multithreading

相信大家都听说过线程和进程，也相信有一部分读者跟我一样常常把它们搞混——这中文翻译得，都有一个程字就是说。
操作系统是有讲过的，**进程（Process）是资源分配的基本单位，线程（Thread）则是 CPU 调度的基本单位。**
我们再详细分析他们的区别：
进程由于其资源是独立的，所以进程之间的通信需要 IPC（Inter-Process Communication）机制，比如管道、消息队列、共享内存等；而线程由于其资源是共享的，所以线程之间的通信就简单多了，直接读写共享变量就行了，创建和切换线程的开销也比进程小得多。

DeepSeek 的类比比较恰当：
**进程**像一个“工厂”：拥有独立的场地（内存）、设备（资源）和工人（线程）。
**线程**像工厂内的“工人”：共享工厂的资源，协作完成生产任务。
**多工厂（多进程）**：需要复制多套场地和设备，成本高，但安全隔离。
**单工厂多工人（多线程）**：效率高但需协调工人避免冲突。

相应地，并发和并行也是有说法的：**多进程对应并行，多线程对应并发**。多进程通过在不同的核上运行任务来实现并行，而多线程则是通过在同一个核上切换任务来实现并发。

### 为什么说 Python 的多线程是伪多线程

一切都缘于 GIL（Global Interpreter Lock），也就是 Python 的全局解释器锁，作为保护访问 Python 对象的线程安全的一种机制，**GIL 使得同一时刻只有一个线程在执行 Python 字节码**，一个线程在执行 Python 字节码时，其他线程只能等待，即线程是交替执行的。

### 总结

I/O 密集型任务使用多线程，CPU 密集型任务使用多进程。
那为什么 I/O 密集型任务不使用多进程呢？
上面已经提到，进程的开销比线程大得多，而且线程间是共享内存的，也意味的 fd 能复用，从而大大提高了 I/O 的效率。

## Golang 又是怎么个事

对 Golang 有一定了解的读者应该知道，Golang 是原生支持并发的，通过一个叫 Goroutine 的东西来实现。

### Goroutine

Goroutine 是一个轻量级线程，之所以轻量，是因为它的**初始栈空间只有 2KB**，而传统线程的栈空间通常需要 MB 级，这差距还是挺大的。

同时 goroutine **运行在用户态**，创建和销毁的开销也比传统线程小得多。

### GMP 模型

Go 运行时通过 **GMP 调度模型** 管理 goroutine 和系统线程的映射关系：

G（Goroutine）：单个协程任务，包含栈、程序计数器等信息。
M（Machine）：操作系统线程（OS Thread），真正执行计算的资源。
P（Processor）：逻辑处理器，管理本地 goroutine 队列（每个 P 绑定一个 M）。

### Channel

Channel 是 goroutine 之间的通信管道，这也是一个神奇的点，goroutine 之间不直接共享内存，而是通过 channel **传递数据**（所有权转移），天然避免并发访问冲突。
这个传递数据过程是一个所有权转移的过程，一旦发送到 channel，发送方就不再持有这个数据，只被接收方独占。而且 **channel 的发送和接收本身都是原子性**的，不需额外加锁。
但是注意这个并不是意味着它完全没有用到锁，观察其底层结构 [hchan 的源码](https://go.dev/src/runtime/chan.go)：

```go
type hchan struct {
    qcount   uint           // total data in the queue
    dataqsiz uint           // size of the circular queue
    buf      unsafe.Pointer // points to an array of dataqsiz elements
    elemsize uint16
    synctest bool // true if created in a synctest bubble
    closed   uint32
    timer    *timer // timer feeding this chan
    elemtype *_type // element type
    sendx    uint   // send index
    recvx    uint   // receive index
    recvq    waitq  // list of recv waiters
    sendq    waitq  // list of send waiters

    // lock protects all fields in hchan, as well as several
    // fields in sudogs blocked on this channel.
    //
    // Do not change another G's status while holding this lock
    // (in particular, do not ready a G), as this can deadlock
    // with stack shrinking.
    lock mutex
}
```

还是可以看到有个互斥锁的，但是**这个锁是用来保护 channel 的内部状态的**，与用户数据并无关系。

### demo

```go
package main

import "fmt"

func worker(jobs <-chan int, results chan<- int) {
    for j := range jobs {  // Receive job from channel
        results <- j * 2  // Send result to channel
    }
}

func main() {
    jobs := make(chan int, 100)
    results := make(chan int, 100)

    // Start 3 worker goroutines
    for i := 0; i < 3; i++ {
        go worker(jobs, results)
    }

    // Send jobs to workers
    for j := 0; j < 5; j++ {
        jobs <- j
    }
    close(jobs)

    // Collect results from workers
    for i := 0; i < 5; i++ {
        fmt.Println(<-results)
    }
}
```

这段代码非常直白，就算没有接触过 Golang 的读者也能看懂大概。
`make(chan int, 100)` 的意思是创建一个容量为 100 的**缓冲通道**（Buffered channel），若为**非缓冲通道**则必须等待接收方准备好才能发送成功，也就是**发送和接收操作必须同步发生**。
缓冲区采用 FIFO 的方式，先发送的先接收。

那么现在就能理解上面那段代码的调度逻辑了：

* 主 goroutine 创建 jobs/results channel。
* 3 个 worker goroutine 被调度到空闲的 P（逻辑处理器）上执行。
* 主 goroutine 发送任务到 jobs channel，worker 竞争接收任务。
* 当 channel 操作阻塞时，调度器自动切换执行的 goroutine。

// To be continued...

## 参考

<https://zm-j.github.io/2022/11/21/python-multiprocessing/>
<https://medium.com/capital-one-tech/python-guide-using-multiprocessing-versus-multithreading-55c4ea1788cd>
<https://zhuanlan.zhihu.com/p/633279726>

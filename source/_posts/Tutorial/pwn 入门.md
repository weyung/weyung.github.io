---
title: pwn 入门
date: 2022-07-18 18:14:00
tags: [CTF, 二进制安全, pwn]
categories: 学习
---

浅记一下这些天学 pwn 的历程
<!--more-->
********************************

## 前言

本文默认读者具有一定的汇编基础。

## ELF文件的结构

**ELF**（Executable and Linkable Format）即 Linux 下的可执行文件格式，和 Windows 下的 **PE** 格式类似，但 Linux 中的可执行文件一般不会加后缀名。
ELF 文件中有多个节（ Section ），主要有：

* **.text** 节：即代码段，用来放代码
* **.rodata** 节：ro 即 read only ，**只读**数据段，用来放静态数据，如果尝试修改会报错
    > `.rdata` 和 `.rodata` 的区别：两者都是只读数据段，但 `.rdata` 是 Windows 的常用说法，而 Linux 中则一般称 `.rodata`
* **.data** 节：数据段，存放**可修改**的数据
* **.bss** 节：中文不知道叫什么名字的段，也是放**可修改**的数据，但是**没有初始化**，所以不占ELF文件的空间，程序运行时会自动分配内存
* **.plt** 节和 **.got** 节：外部调用段（也不知道叫什么名字，这个是 AI 给我打的），调用动态链接库的函数的时候会用到

## Linux下的漏洞缓解措施

有攻就有防，为了不被攻击者随便打烂，一些防范措施是必不可少的。
在终端里可以执行 `checksec --file=文件名` 来查看 ELF 文件的保护机制。

1. **NX** ( No eXecute )(没错 X 就是大写，没打错)
    基本规则为**可写权限**与**可执行权限**互斥，即可被修改写入 shellcode 的内存都不可执行，被执行的代码数据不可修改，至于 shellcode 是啥，后面再提。
    gcc 默认开启，编译加 `-z execstack` 参数可以关闭
2. **Stack Canary**
    Canary 意为金丝雀，以前矿工进入矿井时都会随身带一只金丝雀，通过观察金丝雀的状态来判断氧气浓度等情况。这个保护专门针对栈溢出攻击。
    gcc 同样默认开启，编译加 `fno-stack-protector` 参数关闭
3. **ASLR** ( Address Space Layout Randomization )
    将程序的堆栈地址和动态链接库的加载地址进行一定的随机化
    ASLR 是系统级的保护机制，关闭要修改 /proc/sys/kernel/randomize_va_space 文件，写入 0 即可
4. **PIE** ( Position Independent Executable )
    和 ASLR 类似，让 ELF 的地址随机化加载
    高版本 gcc 默认开启，编译加 `-no-pie` 参数可以关闭，旧版本则需加 `-fpic-pie` 参数开启
5. **Full RELRO** ( Read-Only Relocation )
    禁止写入 `.got.plt` 表
    gcc 编译加 `-z relro` 参数开启。

## GOT和PLT

`.plt` 表是一段代码，可从内存中读取一个地址然后进行跳转，而 `.got.plt` 表则存放函数的实际地址。
实际上，`.got.plt` 表是一个函数指针数组，存放 ELF 所有用到的外部函数在内存中的地址，由操作系统初始化。
题目中如果没开 `Full RELRO` 保护，那么就有可能通过修改 `.got.plt` 表中的函数地址来偷梁换柱，比如把表中 `puts` 的地址换成 `system` 的地址就能使 `puts("\bin\sh")` 变成 `system("/bin/sh")`，从而拿到 shell 。

## 常用工具

1. **IDA**

    拿到程序第一件事——用 IDA 看看伪代码
    分 32 位和 64 位两个版本，**这个打开不行就换另一个**，虽然我也不知道为啥不加个自动识别（）
    把程序拖进去，弹出一个奇怪的选项框，初学者直接 `enter`或者点 `OK` 就完事，然后进到 `IDA View-A` 标签页，这里初始时一般是流程图的形式，在此标签页按空格可以切换到普通模式，**记住不是在 `Pseudocode-A` 按**
    这时候按 `F5` 生成伪代码，看到顶上的标签页切到了 `Pseudocode-A` ， Pseudocode 是伪码的意思，至于这个 A ，你如果再按一次 `F5` 就能新建一个 `Pseudocode-B` 了（）
    然后就可以这点点那点点发现新世界了，嘿嘿
    如下是一些常用的快捷键：
    * 按 `Esc` 可以返回刚才的页面
    * 按 `Tab` 可以在 `IDA View-A` 和 `Pseudocode-A` 等标签页之间切换
    * 双击函数或者变量可以跳转到它所在的地方
    * 点一下变量再按 `N` 可以对变量重命名，有时方便分析
    * `Shift+F12` 查找字符串
2. **pwntools**

    python 的一个库，可以用与远程服务器或者本地程序交互，但不保证在 Windows 下能正常使用（反正我 Windows 跑 pwntools 是有问题的
    常用操作：
    * `r = process("./pwn")` 本地运行程序（其实本地一般用 `p` 作变量表示process或者`io`兼顾本地和远程，看个人习惯了
    * `r = remote(ip, port)` 连接服务器
    * `r.sendline(data)` 发送数据，末尾补 `\x0a`（换行符）
    * `r.send(data)` 发送数据，末尾不补 `\x0a`
    * `r.recvline()` 接收一行数据
    * `r.recvuntil(str)` 接收直到遇到 `str` 为止
    * `r.recv(n)`接收 `n` 个字节
    * `r.interactive()` 开始人工手动交互

    pwntools 在 python3 中使用的话，交互的数据都是 `bytes` 类型，而不是 `str` 类型，意思就是 `send` 里的东西要是字节串， `recv` 出来的也是字节串，字符串转字节方法一般是 `str.encode()` ，或者 `send(b'hello')`
3. **pwndbg**

    pwn 里面少不了本地调试，正常人都不能肉眼分析，那么就要用到 gdb ，but 裸的 gdb 太朴素了，不能满足人们日益增长的对优雅的追求，所以就有了**颜值极高**的 gdb 插件—— pwndbg
    安装方式：

    ```bash
    git clone https://github.com/pwndbg/pwndbg
    cd pwndbg
    ./setup.sh
    ```

    然后康康 `~/.gdbinit` 里有没有 `source ~/pwndbg/gdbinit.py` ，如果没有就加上，然后 `source ~/.gdbinit` ，然后就可以愉快地玩耍了
    在 VSCode 里起 gdb 要用 tmux ，直接 `sudo apt-get install tmux` 安装
    > **tmux的简单使用**：
    `tmux` 进入窗口
    `tmux ls` 查看会话列表
    `Ctrl+B` `左右键` 切换会话窗口，一般默认左右分布，也可调成上下
    `Ctrl+B` `D` 退出当前会话但不关闭，可以 `tmux attach -t <会话名>` 再次进入

    脚本里可以使用如下语句起 gdb：

    ```python
    p = process('./pwn')
    context.terminal = ['tmux','splitw','-h']
    gdb.attach(p,gdbscript="b main")
    ```

    pwndbg 界面由上至下依次为
    * **legend**：图例，一般指示黄色为 Stack（栈），蓝色为 Heap（堆），红色为 Code（代码），紫色为 Data（数据），白色下划线为RWX（不知道啥），白色为 Rodata（只读数据）
    * **registers**：显示 CPU 的寄存器值
    * **disasm**：显示当前地址的反汇编代码
    * **stack**：显示栈的内容
    * **backtrace**：显示调用堆栈（我也不知道具体干嘛的）

    常用操作：
    * `x/4xg 0x400000` 查看内存中地址 `0x400000` 开始的 4*16 个字节，以 8 个字节每组的 16 进制形式显示，一般在分析 64 位程序时使用，因为 64 位程序的地址是 8 个字节， 32 位时，命令可以换成 `x/4x` ，每组 4 个字节，适用 32 位程序的地址
    * `ni` 也就是 next into ，执行下一条指令，如果是函数调用，就进入函数
    * `si` 也就是 step into ，执行下一条指令，如果是函数调用，就进入函数，但是不会执行函数内的第一条指令，而是停在函数内的第一条指令上
    * `c` continue ，继续执行，直到遇到断点或者程序结束
    * `q` quit ，退出 gdb
    * `vmmap` 查看内存映射，可以看到程序的基地址，栈地址，堆地址等，后面加个 `libc` 可以单看 libc 的基地址（白色的那行
    * `set` 改变变量的值，比如 `set $eax=0` 就把 eax 的值改成了 0
    * `b` 设置断点，后面加地址或者函数名，比如 `b *0x400000` 或者 `b main` ，后者是在 main 函数入口处设置断点，或者 `b *main+111` 在 main 函数的第 111 条指令处设置断点

## 常见攻击方式

### 整数溢出

这个比较简单，大概就是通过溢出绕过一些大小判断，不再赘述。

### 栈溢出

先说几个概念
执行 call 指令时， CPU 会先把 call 指令的下一条指令地址压栈再跳转，返回时 ret 指令会从栈中把存放的地址弹出到 EIP 。
gets 不检查读入的字符串长度，所以可能会出现栈溢出。
当栈作为缓冲区时，如果输入的数据长度超过缓冲区的长度，就会发生栈溢出，从而覆盖返回地址，从而控制程序流程。

未完待续...

## 参考

* 《从0到1：CTFer成长之路》——Nu1L战队[著]
* 《CTF竞赛权威指南.Pwn篇》——杨超[著]
* <https://blog.csdn.net/sui_152/article/details/121650341>
* <https://stackoverflow.com/questions/65745514/what-is-the-difference-between-rodata-and-rdata>
* <https://blog.csdn.net/weixin_52553215/article/details/120690453>
* <https://blog.csdn.net/zino00/article/details/122716412>
* <https://blog.csdn.net/Demondai999/article/details/123875264>

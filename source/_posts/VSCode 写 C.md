---
title: VSCode 写 C
date: 2021-12-29 10:10:53
tags: [VSCode, C]
categories: 环境搭建
---

一句话：VSCode 确实是一个好东西
<!--more-->
## 前言

> 在用 VSCode 前，我写 C 一直用的是 VS2019 ，直到我看见了 GZTime 学长写的 [Visual Studio Code Guide](https://blog.gztime.cc/posts/2020/6b9b4626/) 一文并照着配了后，我乐了，原来 VSCode 如此好用。首先作为一个编辑器，它比 VS2019 这个 IDE 小了太多（一个几十 MB ，一个 10 个 GB ），其次，它配上 gcc 可以避免 VS2019 由于 msvc 导致的 `scanf_s` 等一堆 `_s`（或许我的表述不是太严谨，但差不多是这个意思）。
> 本文高度概括了学长的文章，说是转载也不为过，读者根据自身水平可酌情移步至[原文](https://blog.gztime.cc/posts/2020/6b9b4626/)。

## 安装

### 链接

[下载链接](https://wwi.lanzouw.com/b00v71rpc)

### 注意事项

1. 安装 gcc 时**取消勾选** `Check for updated files on the TDM-GCC server`。
2. 安装 VSCode 时在附加任务中“其他”中的**四项全部勾选**，即将用 Code 打开加入文件和文件夹添加入右键菜单中，并注册为受支持的文件类型的编辑器。
3. 不推荐更改**默认文件夹**（别抠这点空间了）。

### 普通配置

安装好 VSCode 和 gcc 后，**重启电脑**，运行 VSCodeCppHelper ，如果你对在哪创建文件夹没有好的选择，就把 VSCodeCppHelper 放 C 盘随便一个地方里运行，然后傻瓜式 `enter` 。

### 机房里配置

> 由于 GZTime 学长写的 VSCodeCppHelper 小工具需要重启才能识别出 VSCode 和 gcc 的安装，但是机房的电脑一重启所有东西又会全部重置，此时便只能手动配置了。（以下均为转载）
_更新：如今 VSCodeCppHelper 已经支持在没检测到环境变量的情况下进行配置了。_

1. 打开 VSCode 至你的文件夹（此处以 `C:\Coding` 为例）。
2. 打开左侧 `Extensions` 选项卡，搜索 C++ 并安装 `C/C++` 和 `C/C++ Intellisence` 两个扩展。
3. 在根目录新建文件夹 `Scripts` 以及 `Debug`
4. 在 `Scripts` 文件夹中新建文件 helloworld.cpp ，写下传统的 helloworld 程序：

    ```C++
    #include <bits/stdc++.h>
    using namespace std;
    int main()
    {
      cout << "Hello world!" << endl;
      return 0;
    }
    ```

5. 单击左侧菜单中的运行并点击运行和调试，选择 **C++(GDB/LLDB)** 。
6. 此时 VSCode 会在你的根目录下新建 `.vscode` 文件夹，此文件夹中用于存放 VSCode 的相关配置文件，打开 `launch.json` 替换或修改为如下内容：

    ```json
    {
      // 使用 IntelliSense 了解相关属性。
      // 悬停以查看现有属性的描述。
      // 欲了解更多信息，请访问: https://go.microsoft.com/fwlink/?linkid=830387
      "version": "0.2.0",
      "configurations": [
      

        {
          "name": "C++ Run",
          "type": "cppdbg",
          "request": "launch",
          "program": "${workspaceRoot}/Debug/${fileBasenameNoExtension}.exe", //运行文件的路径
          "args": [],
          "stopAtEntry": false,
          "cwd": "${workspaceFolder}",
          "environment": [],
          "console": "internalConsole",
          "internalConsoleOptions": "neverOpen",
          "MIMode": "gdb",
          "miDebuggerPath": "C:/TDM-GCC-64/gdb64/bin/gdb.exe",
          "setupCommands": [
            {
              "description": "为 gdb 启用整齐打印",
              "text": "-enable-pretty-printing",
              "ignoreFailures": true
            }
          ],
          "preLaunchTask": "Compile" //运行前需要完成的任务
        },
        {
          "name": "C Run",
          "type": "cppdbg",
          "request": "launch",
          "program": "${workspaceRoot}/Debug/${fileBasenameNoExtension}.exe", //运行文件的路径
          "args": [],
          "stopAtEntry": false,
          "cwd": "${workspaceFolder}",
          "environment": [],
          "console": "internalConsole",
          "internalConsoleOptions": "neverOpen",
          "MIMode": "gdb",
          "miDebuggerPath": "C:/TDM-GCC-64/gdb64/bin/gdb.exe",
          "setupCommands": [
            {
              "description": "为 gdb 启用整齐打印",
              "text": "-enable-pretty-printing",
              "ignoreFailures": true
            }
          ],
          "preLaunchTask": "Compile_C" //运行前需要完成的任务
        }
      ]
    }
    ```

7. 在 `.vscode` 文件夹中新建文件 `tasks.json` 并输入如下内容：

    ```json
    {
      "version": "2.0.0",
      "tasks": [
        {
          "label": "Compile",
          "command": "g++",
          "args": [
            "-g",
            "${file}", //指定编译源代码文件
            "-o",
            "${workspaceRoot}\\Debug\\${fileBasenameNoExtension}.exe", // 指定输出文件名，不加该参数则默认输出a.exe
            "-ggdb3", // 生成和调试有关的信息
            "-Wall", // 开启额外警告
            "-static-libgcc", // 静态链接
            "-std=c++2a",
            "-Wno-format",
            "-finput-charset=UTF-8", //输入编译器文本编码 默认为UTF-8
            "-fexec-charset=UTF-8" //编译器输出文本编码 自行选择
          ],

          "type": "shell",

          "presentation": {
            "echo": true,
            "reveal": "silent", // 在“终端”中显示编译信息的策略，可以为always，silent，never
            "focus": false,
            "panel": "shared", // 不同的文件的编译信息共享一个终端面板
            "clear": true,
            "showReuseMessage": true
          },

          "problemMatcher": {
            "owner": "cpp",
            "fileLocation": ["relative", "\\"],
            "pattern": {
              "regexp": "^(.*):(\\d+):(\\d+):\\s+(warning|error):\\s+(.*)$",
              "file": 1,
              "line": 2,
              "column": 3,
              "severity": 4,
              "message": 5
            }
          }
        },
        {
          "label": "Compile_C",
          "command": "gcc",
          "args": [
            "-g",
            "${file}", //指定编译源代码文件
            "-o",
            "${workspaceRoot}\\Debug\\${fileBasenameNoExtension}.exe", // 指定输出文件名，不加该参数则默认输出a.exe
            "-ggdb3", // 生成和调试有关的信息
            "-Wall", // 开启额外警告
            "-static-libgcc", // 静态链接
            "-Wno-format",
            "-finput-charset=UTF-8", //输入编译器文本编码 默认为UTF-8
            "-fexec-charset=UTF-8" //编译器输出文本编码 自行选择
          ],

          "type": "shell",

          "presentation": {
            "echo": true,
            "reveal": "silent", // 在“终端”中显示编译信息的策略，可以为always，silent，never
            "focus": false,
            "panel": "shared", // 不同的文件的编译信息共享一个终端面板
            "clear": true,
            "showReuseMessage": true
          },

          "problemMatcher": {
            "owner": "cpp",
            "fileLocation": ["relative", "\\"],
            "pattern": {
              "regexp": "^(.*):(\\d+):(\\d+):\\s+(warning|error):\\s+(.*)$",
              "file": 1,
              "line": 2,
              "column": 3,
              "severity": 4,
              "message": 5
            }
          }
        }
      ]
    }
    ```

8. 类似的，配置 `c_cpp_properties.json` ，这个我不知道要不要（逃

    ```json
    {
      "configurations": [
        {
          "name": "Win32",
          "includePath": [
            "${workspaceFolder}/**"
          ],
          "defines": [
            "_DEBUG",
            "UNICODE",
            "_UNICODE"
          ],
          "compilerPath": "C:/TDM-GCC-64/bin/g++.exe",
          "cStandard": "c11",
          "cppStandard": "c++20",
          "intelliSenseMode": "gcc-x64",
          "macFrameworkPath": [],
          "browse": {
            "path": [
              "C:/TDM-GCC-64/lib/gcc/x86_64-w64-mingw32/10.3.0/include/*",
              "C:/TDM-GCC-64/lib/gcc/x86_64-w64-mingw32/10.3.0/include/c++/*"
            ]
          }
        }
      ],
      "version": 4
    }
    ```

搬砖完毕（逃

## 中文乱码

VSCode 中默认终端常为 PowerShell ，Windows 10 中 PowerShell 默认编码跟随系统，可以通过修改区域设置来改变默认编码： 控制面板->区域->更改系统区域设置->勾选 `Beta版：使用Unicode:UTF-8以获取全球语言支持`，但这样可能会造成其他应用乱码，笔者就因为这个事情改回去了。

## VSCode 使用的注意事项

> 虽说 VSCode 好，但有几点注意的，被坑过。。。

1. 不要直接**在文件夹双击打开 .c 文件**启动 VSCode
2. 不要给 .c 文件起**中文名**
3. 不要在**其他文件夹**（除了你最初配置好的文件夹，比如桌面）中启动 VSCode
4. 以上配置无法进行**多文件编译**
5. 以上说法仅针对初学者，均不严谨

## 参考

> [Visual Studio Code Guide](https://blog.gztime.cc/posts/2020/6b9b4626/) by GZTime
<https://blog.csdn.net/m0_55005568/article/details/119960552>

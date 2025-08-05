---
title: Linux 学习笔记
date: 2022-07-07 21:00:00
tags: [Linux]
categories: 学习
---

最近用到 Linux 挺多，整理一下。
<!--more-->

## 终端美化

一个好看的终端确实是第一生产力

```bash
# 安装 oh-my-posh
sudo wget https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/posh-linux-amd64 -O /usr/local/bin/oh-my-posh
sudo chmod +x /usr/local/bin/oh-my-posh
# 下载主题
mkdir ~/.poshthemes
wget https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/themes.zip -O ~/.poshthemes/themes.zip
unzip ~/.poshthemes/themes.zip -d ~/.poshthemes
chmod u+rw ~/.poshthemes/*.omp.*
rm ~/.poshthemes/themes.zip
```

`oh-my-posh get shell` 看看 shell，一般是 bash 的情况下，就在 `~/.bashrc`（也可能是 `~/.profile` 或 `~/.bash_profile`）文件追加一行

```bash
eval "$(oh-my-posh init bash --config ~/.poshthemes/.kali.omp.json))" # kali为主题名称，可以自己更换其他的
```

说起来这个 kali 主题还是 GZTime 学长提的 pr ，当时他还打成了 kail 来着（笑
然后执行以下命令重载配置文件：

```bash
exec bash
```

> oh-my-posh 官方文档：<https://ohmyposh.dev/docs/>

## 换源

CentOS 默认已经调好阿里源了，就不用换了，以下是 apt 换中大源的方法：

```bash
sudo vim /etc/apt/sources.list
```

按 `i` 切换到编辑模式，然后全删了，写入 `deb https://mirrors.matrix.moe/kali kali-rolling main non-free contrib`，`Esc` 键退出编辑模式，`:wq` 保存退出。

更新软件源列表：

```bash
sudo apt update
```

## ssh配置

想起我闲置的阿里服务器，又折腾了好久。
首先新建用户： `adduser <用户名>` 并设置好密码（网上说 CentOS 下的 adduser 和 useradd 是一样的，但我用的时候他也给我一整套配下来了，`home` 下也有文件夹。）

```bash
su <用户名>
ssh-keygen -t rsa   #生成密钥对，一路回车就行
cd ~/.ssh
cat id_rsa.pub >> authorized_keys   #把密钥添加到authorized_keys文件中
chmod 600 authorized_keys
chmod 700 ~/.ssh    #权限700的时候，sshd才能读到
service sshd restart    #重启sshd服务
```

## 权限说明

一般用三个数字表明文件的权限，第一个数字表示用户，第二个数字表示组，第三个数字表示公共。

4 表示可读， 2 表示可写， 1 表示可执行，加一起就是全部权限。
比如 755 表示用户可读，可写，可执行，组可读，可执行，公共可读，可执行。

可能你会问 222 权限啥意思，难道还能只写不读？
其实还真是这样，笔者试过可以 `cat >> file` 进行追加写入，但不能读取文件内容。

遇到文件执行不了的情况，试试 `chmod +x [file]` ，就有执行权限了。

## 编辑器（vim）

虽然有 VSCode 的存在，但有时候由于 ssh 的用户权限不够等原因不可避免地要用到 vim （当然硬要避免也有在其他地方写好再 cp 过去等诡方法，但总是麻烦着点）
vim 的三个模式：**命令**模式（ Command mode ），**输入**模式（ Insert mode ）和**底线命令**模式（ Last line mode ）
一般就按 `i` 进入编辑模式， `Esc` 退出编辑模式并 `:wq` 保存退出。
在查看模式下，可以 `h` 左移， `j` 下移， `k` 上移， `l` 右移，按 `/` 可以搜索。

## 常用命令

> 命令行 without 鼠标确实爽。

### chown

即 change owner ，用于改变文件的所有者。

一般 `chown [user] [file]` ，如果是目录还要加上 `-R` 参数，意为改变目录下所有文件的所有者。

### ln

即 link ，用于创建符号链接，和 Windows 的快捷方式类似。

一般 `ln -s [old] [new]` ，就是创建一个符号链接，把 old 文件的内容链接到 new 文件，如果后面不加 `[new]` 参数，那么就会默认创建到当前目录下。

### ps

即 process status ，用于查看进程状态。

一般加 -aux 显示所有包含其他使用者的进程。
不过这只是一个快照，如果想看动态的，就用 [top](#top) 命令。

### top

没啥缩写了，就是 top ，用于实时显示进程的状态。

### grep

```bash
grep "pattern" filename # 在文件中查找 pattern 字符串
grep -r "pattern" directory # 在目录中递归查找 pattern 字符串
```

### du

```bash
du -h --max-depth=1 | sort -h   # 查看当前目录下各文件夹大小
```

## 参考

<https://www.lxlinux.net/1431.html>
菜鸟教程
<https://blog.csdn.net/KevinChen2019/article/details/119697489>
<https://blog.csdn.net/lucky__peng/article/details/124268817>
<https://blog.csdn.net/liuxiao723846/article/details/125042549>

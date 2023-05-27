---
title: Squid 代理简记
date: 2023-05-14 19:40:00
tags: [Linux, 代理]
categories: 环境搭建
---

ChatGPT 确实是好东西
<!--more-->

## 前言

之前一直用的 ChatGPT 的号还是当时淘宝买的，还充了 Plus，但是不能改密码，有点强迫症，就想自己开个号。
现在 ChatGPT 的号注册越来越麻烦了，万人骑的机场的 IP 已经被 ban 干净了，前几天就拜托一个新加坡的学长帮忙用自己邮箱的号开了个号，后继又想再帮同学开几个，但总不好一直叨扰学长，就想自己搭个梯子。

## 服务器

问一个微软学生大使的同学在 Azure 开了台美国的机子（学生邮箱也可以白嫖），但是 SSH 老是连不上，一试发现是校园网的问题，用我阿里云的服务器去 SSH 就能稳定连上，再不久也发现原来我机场梯子老掉也是校园网的缘故，用阿里云的机子走机场稳定秒开 Google，当时我就气炸了。
最终的方案是用阿里云的机子当跳板机去 SSH 美国的机子，`./ssh/config` 配置如下

```bash
Host <你想叫啥就叫啥>
  HostName <x.x.x.x>
  User <user>
  IdentityFile <~/.ssh/US.pem>
  ProxyCommand ssh -W %h:%p <aliyun>
```

<> 里的内容自行替换。

## Squid

Squid 这个东西是 ChatGPT 推荐的，可以直接在机子开个 http 代理，简单方便。安装也是直接 `sudo apt install squid` 就行，然后把 `/etc/squid/squid.conf` 改成如下（不会用 vim 可以用 nano）：

```bash
# ACLs all, manager, localhost, and to_localhost are predefined.
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# 拒绝所有非 Safe_ports 的请求
http_access deny !Safe_ports

# 拒绝所有非 SSL_prots 的 CONNECT请求
http_access deny CONNECT !SSL_ports

# 允许来自本地的请求
http_access allow localhost

# 拒绝所有请求，最后兜底的规则
http_access deny all

# 端口设为 3128
http_port 3128

# 高匿代理配置
request_header_access Via deny all
request_header_access X-Forwarded-For deny all
request_header_access From deny all
```

然后 `sudo systemctl restart squid`，要等上一会，我应该等了差不多半分钟。

然后我端口转发搞了一天，失败得莫名其妙的，最终就直接用 VSCode SSH 后自带的端口转发顶着先了。

更新：后来用 SSH 的端口转发了，命令如下：

```bash
ssh -N -L 0.0.0.0:55555:localhost:3128 <your-azure>
```

这样就可以在本地的 55555 端口访问到远程的 3128 端口了，`0.0.0.0` 是想给同一局域网的其他机子接，不需要的话可以只写端口，`-N` 意思是不启动远程 shell，如果你希望在后台运行可以再加个 `-f`。
但是这样不够优雅，就再搞了个 systemd 的服务，配置如下：

```bash
# /etc/systemd/system/ssh-tunnel.service
[Unit]
Description=SSH tunnel service
After=network.target

[Service]
ExecStart=/usr/bin/ssh ssh -N -L 0.0.0.0:55555:localhost:3128 <your-azure>
User=<你的用户名>
Restart=always

[Install]
WantedBy=multi-user.target
```

然后 `sudo systemctl daemon-reload` 一下，再 `sudo systemctl start ssh-tunnel` 就行了，`sudo systemctl enable ssh-tunnel` 可以设置开机自启。

## 参考

* <https://zhuanlan.zhihu.com/p/562014043>

# openssl 解密



## 简介

运行平台： windows 10 专业版 （版本 22H2）

开发工具：VS2019 社区版

开发语言：C 语言

Wireshark：4.6.0， 抓包分析工具

cmake：4.0.4，编译工具



| 开源代码 | 版本   | 备注                           |
| -------- | ------ | ------------------------------ |
| nginx    | 1.28.0 | https 服务器，可执行程序       |
| openssl  | 3.5.4  | SSL 协议，网站下载编译好的SDK  |
| libpcap  | 1.10.5 | 源代码编译，动态链接库         |
| npcap    | 1.15   | 网站下载 SDK，用于编译 libpcap |
| llhttp   | 9.3.0  | 解析 http 头，静态链接库       |



最终的可执行程序：openssl_dec.exe

功能：openssl 解密https 包

工程的目的：学习 openssl 开源库，学习 TLS 通讯协议

------



## 使用



程序输入：release\res\s_connect.pcapng ， 客户端ECDHE私钥（写在代码中）

程序功能：测试从 ECDHE 私钥到最终密钥的计算，解密 https

程序输出： index.html

程序输出是否正确，可以和 release\res\index.html  对比。

两个文件一样，则输出正确。



------

# 目录说明



## include

开源库头文件

openssl：openssl 头文件

pcap：libpcap 头文件

llhttp.h：llhttp 头文件

libnet.h：IP/TCP 头定义



## libs

动态链接库的符号表

llhttp 静态链接库



## openssl_dec

VS2019 工程文件



## release

可执行程序，动态链接库

编译结果：openssl_dec.exe

程序运行需要以下3个头文件：

Packet.dll， pcap.dll， libcrypto-3-x64.dll



## src

源代码目录。

cipher.c：加密，解密

main.c：主程序入口

parse.c：TLS 包解析

cert.c：https 证书

t1_trce.c：一些字符串资源。从openssl源代码拷贝 openssl-3.5.4\ssl\t1_trce.c

tools.c：一些小工具



------



# 资源



程序输入资源如下：

release\res\s_connect.pcapng：Wireshark 抓取的 TLS 通讯



如何产生 s_connect.pcapng，以下具体说明。



## 1 - 搭建服务器

[openssl-2-搭建https服务器 - 知乎](https://zhuanlan.zhihu.com/p/1958572249872332446)

在本地电脑上搭建 https 服务器。

```bash
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout RootCA.key -out RootCA.crt -subj "/C=CN/CN=albert-CA"

openssl req -new -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj "/C=CN/CN=albert"

openssl x509 -req -sha256 -days 1024 -in server.csr -CA RootCA.crt -CAkey RootCA.key -extfile domains.ext -out server.crt
```

以上命令行输出的文件 RootCA.crt， server.key， server.crt

RootCA.crt：根证书，安装到win10 操作系统中： **受信任的根证书颁发机构**

**server.crt**：本地 https 服务器的证书文件

**server.key**：本地 https 服务器的密钥文件

把这两个文件拷贝到 nginx\ssl 目录下

```nginx
ssl_certificate      ./ssl/server.crt;
ssl_certificate_key  ./ssl/server.key;
```



## 2 - wireshark 抓包

运行 nginx 服务器：命令行运行

```
nginx.exe
```



然后用 wireshark 抓取本地 loopback 网口的通讯，过滤条件：

```
tls or http
```



命令行运行：

```bash
printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' / localhost | openssl s_client -quiet -connect localhost:443 -keylogfile wireshark_keys.log
```



抓包后，导出特定分组

wireshark ：文件 - 导出特定分组 - 仅选中分组，保存为文件：

**s_connect.pcapng**

这个文件作为程序的输入。

![wireshark_s_connect](.\release\res\wireshark_s_connect.jpg)



------

# libpcap

解析 wireshark 抓包格式：pcapng 格式，需要用到开源软件库 libpcap

编译 libpcap 需要用到 npcap



## npcap SDK

下载 npcap SDK 1.15

[Npcap: Windows Packet Capture Library & Driver](https://npcap.com/#download)

npcap-sdk-1.15.zip



## libpcap

下载 libpcap 源代码，V1.10.5

[Home | TCPDUMP & LIBPCAP](https://www.tcpdump.org/index.html#latest-releases)

doc\README.windows.md， 说明了编译方法。



## winflexbison

需要安装 winflexbison 工具，这里

https://sourceforge.net/projects/winflexbison/



下载 win_flex_bison3-latest.zip， 解压，假设解压到

D:\tools\win_flex_bison-latest

把这个路径加到系统路径中



## 编译

假设安装目录是 R:/libs

npcap-sdk-1.15.zip 解压到 R:/npcap-sdk-1.15



用 cmake 编译

解压 libpcap-1.10.5.tar.xz，

 cmake 打开根目录，然后设置变量：

```bash
CMAKE_INSTALL_PREFIX=R:/libs  
Packet_ROOT=R:/npcap-sdk-1.15
DISABLE_DPDK=ture
CMAKE_SUPPRESS_DEVELOPER_WARNINGS=true
ENABLE_REMOTE=false
```

ENABLE_REMOTE=false，告诉编译器无需链接 OpenSSL 库。

![cmake](.\release\res\cmake.jpg)

点击：configure, generate，生成 VS2019 工程项目





VS2019 打开 pcap.sln

选择 release x64，开始编译

编译之后，再编译 INSTALL  项目，就会安装到 R:/libs  



## 编译结果

使用动态链接库

pcap.dll: 432KB

pcap.lib : 24KB



## 使用

[Npcap: Windows Packet Capture Library & Driver](https://npcap.com/)

下载 [Npcap 1.84 installer](https://npcap.com/dist/npcap-1.84.exe) for Windows

npcap-1.84.exe

安装到默认位置：

C:\Windows\System32\Npcap

这个目录下有文件：Packet.dll

pcap.dll， Packet.dll 拷贝到程序运行目录下。

pcap.dll 是libpcap 编译的结果；

pcap.dll 运行时依赖 Packet.dll。



------

# 学习资源

书籍：深入浅出 HTTPS——从原理到实战 (虞卫东)

RFC 5246： TLS1.2，最核心的文档

RFC8446：TLS1.3

RFC 5280： X.509 证书

RFC 2818：HTTP Over TLS，HTTPS

OpenSSL 源代码： 用 gvim, ctags, csope, grep 工具分析学习



# 相关文章



[http 访问流程 - 知乎](https://zhuanlan.zhihu.com/p/28812758850)



[openssl-1-编译和使用 - 知乎](https://zhuanlan.zhihu.com/p/1957352813823791848)

[openssl-2-搭建https服务器 - 知乎](https://zhuanlan.zhihu.com/p/1958572249872332446)

[openssl-3-https 证书 - 知乎](https://zhuanlan.zhihu.com/p/1958804560513574760)

[openssl-4-签名 - 知乎](https://zhuanlan.zhihu.com/p/1959162981024798613)



## openssl-dec 项目

[openssl-5-立项openssl-dec - 知乎](https://zhuanlan.zhihu.com/p/1960580134147958148)

[openssl-6-加密1-综述 - 知乎](https://zhuanlan.zhihu.com/p/1961814328685592981)

[openssl-7-加密2-预备主密钥 - 知乎](https://zhuanlan.zhihu.com/p/1962394065057325443)

[openssl-8-加密3-中间密钥 - 知乎](https://zhuanlan.zhihu.com/p/1963179645064175907)

[openssl-9-加密4-终极密钥 - 知乎](https://zhuanlan.zhihu.com/p/1965067420050912596)

[openssl-10-加密5-解密https - 知乎](https://zhuanlan.zhihu.com/p/1965295237258785537)



# 注意

2025/10/13 Openssl 库换成 debug 版本，记着将来发行时换回来。



------



# 开发日志



## 2025年

10/11：开始开发

10/13 ：Openssl 库换成 debug 版本，可以调试源代码级别的 Openssl 库。

10/21： 完成 Server Hello 解密

10/22：完成 Server Hello， verify_data 的验证，难

10/23：完成 s_connect.pcapng 包的解析

10/24：一次抓包，可以记录 ECDHE 私钥（所有会话密钥）和下载网页;

10/25：完成解析，并且下载https 通讯中的网页 index.html 到本地。


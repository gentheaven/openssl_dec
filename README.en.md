# openssl decode

#### Description

input : release\res\s_connect.pcapng,  ECDHE private key

output:  index.html

Function: decode TLS traffic

```
const char local_prikey_str[] = "60c436e016e222581407cd72eb98fd81877414960a23041f5b8d2868dbbbe765";
unsigned char local_prikey[32];
str2hex(local_prikey_str, sizeof(local_prikey_str), local_prikey);
```




#### Software Architecture

OS: windows 10 22H2

IDE: VS2019

language:  C

Wireshark: 4.6.0

cmake: 4.0.4



| Open Source | version | comments                |
| ----------- | ------- | ----------------------- |
| nginx       | 1.28.0  | https web server        |
| openssl     | 3.5.4   | SDK                     |
| libpcap     | 1.10.5  | parse Wireshark packets |
| npcap       | 1.15    | used to compile libpcap |
| llhttp      | 9.3.0   | parse http header       |



compile result: openssl_dec.exe



#### Installation

1.  xxxx
2.  xxxx
3.  xxxx

#### Instructions

1.  xxxx
2.  xxxx
3.  xxxx

#### Contribution

1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request


#### Gitee Feature

1.  You can use Readme\_XXX.md to support different languages, such as Readme\_en.md, Readme\_zh.md
2.  Gitee blog [blog.gitee.com](https://blog.gitee.com)
3.  Explore open source project [https://gitee.com/explore](https://gitee.com/explore)
4.  The most valuable open source project [GVP](https://gitee.com/gvp)
5.  The manual of Gitee [https://gitee.com/help](https://gitee.com/help)
6.  The most popular members  [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)

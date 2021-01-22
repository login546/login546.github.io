---
title: 2019工业信息安全技能大赛个人线上赛第一场writeup
date: 2019-07-29 10:25:16
toc: true
tags: 
- ices
- 2019年工业信息安全技能大赛个人线上赛(第一场)
categories: 
- ctf 
---

# 2019年工业信息安全技能大赛个人线上赛(第一场)writeup

## 1.1.Modbus协议分析（签到题）[未解决]

题目：黑客通过外网进入一家工厂的控制网络，之后对工控网络中的操作员站系统进行了攻击，最终通过工控协议破坏了正常的业务。我们得到了操作员站在攻击前后的网络流量数据包，我们需要分析流量中的蛛丝马迹，找到FLAG。

附件下载：[1.1.Modbus协议分析（签到题）](https://www.lanzous.com/b864349)

利用[scu--igroup](https://github.com/scu-igroup/ctf_ics_traffic)得到如下

![6ED8204B-0D39-46CB-A487-722EDF12AD8C](https://user-images.githubusercontent.com/38073810/62021762-72a78680-b1fb-11e9-86d4-e1ea755eeb60.png)

得到的是16进制，我目前暂未解决，但是感觉就是70，我们去[转换字符](https://www.bejson.com/convert/ox2str/)，得到

![image](https://user-images.githubusercontent.com/38073810/62021779-8f43be80-b1fb-11e9-973b-4ec0d546bb66.png)

去提交，试了好多种格式，还是不对，可能不是这个包吧（逃。

### 注：

比赛结束后，经人指点，说我这个包不是签到题的那个，我。。。。。我再去下载一看还真不是，难道是我搞错了？

莫名其妙。 下面是我找到的flag，瑟瑟发抖。麻痹大意。（逃。

![image](https://user-images.githubusercontent.com/38073810/62022554-7937fd00-b1ff-11e9-81cf-24aad5c6ea6a.png)

## 1.2.工业协议分析1

题目：工业网络中存在异常，尝试通过分析PCAP流量包，分析出流量数据中的异常点，并拿到FLAG。

附件下载：[1.2.工业协议分析1](https://www.lanzous.com/b864350)

首先利用[scu--igroup](https://github.com/scu-igroup/ctf_ics_traffic)大佬的脚本跑了下，未发现有用的信息。之后放到kali里面搜了下关键词png，发现了base64加密的图片

![6C87E706BFE7D1B12BA8637FCA6E6856](https://user-images.githubusercontent.com/38073810/62021793-a4b8e880-b1fb-11e9-80c9-fbede62bb56c.jpg)

导出数据

```php+HTML
data:image/png;base64,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
```

解密得到图片

![image](https://user-images.githubusercontent.com/38073810/62021805-b7332200-b1fb-11e9-8675-cee79a5bcb1a.png)

## 1.3.工业协议分析2

题目：在进行工业企业检查评估工作中，发现了疑似感染恶意软件的上位机。现已提取出上位机通信流量，尝试分析出异常点，获取FLAG。

附件下载：[1.3.工业协议分析2](https://www.lanzous.com/b864351
)

wireshark打开后直接审计出的，你会发现好多包里都有这串16进制的数。

![image-20190729110250337](https://user-images.githubusercontent.com/38073810/62021816-c6b26b00-b1fb-11e9-9214-b9096b5e4a70.png)

copy，我们去[转换字符](https://www.bejson.com/convert/ox2str/)，得到flag{7FoM2StkhePz}，提交格式：7FoM2StkhePz

## 1.4.组态软件安全分析

题目：一些组态软件中进行会配置连接很多PLC设备信息。我们在SCADA 工程中写入了flag字段，请获取该工程flag

附件下载：[1.4.组态软件安全分析](https://www.lanzous.com/b864352
)

首先下载附件得到test.PCZ文件，直接文本打开发现是以PK开头的文件

![image-20190729111216252](https://user-images.githubusercontent.com/38073810/62021818-d29e2d00-b1fb-11e9-9784-1c48124859b6.png)

修改后缀为zip，打开发现一个文件夹，一个xml(加密，暂时不管)，然后把文件夹拖到mac里直接使用命令搜索flag

```bash
find . -exec cat {} \; |grep -a "flag"
```

![image-20190729111729563](https://user-images.githubusercontent.com/38073810/62021826-e184df80-b1fb-11e9-8343-107eedc90749.png)

得到flag{D076-4D7E-92AC-A05ACB788292}，提交格式：D076-4D7E-92AC-A05ACB788292

## 1.5.工控蜜罐日志分析

题目：工控安全分析人员在互联网上部署了工控仿真蜜罐，通过蜜罐可抓取并分析互联网上针对工业资产的扫描行为，将存在高危扫描行为的IP加入防火墙黑名单可有效减少工业企业对于互联网的攻击面。分析出日志中针对西门子私有通信协议扫描最多的IP，分析该扫描组织。FLAG为该IP的域名。

附件下载：[1.5.工控蜜罐日志分析](https://www.lanzous.com/b864354
)

解压附件到本地，得到honeypot.log。直接提取ip，去重。

```bash
cat honeypot.log | grep -o '\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}'|sort -d | uniq  >> IPFile2.txt
```

然后nslookup反查域名。

```python
flie = open('IPFile2.txt','r')
import os

ip = list()

count = [0 for i in range(0,600)]

ip.append(flie.readline())

while True:
    line = flie.readline()
    if not line:
        break
    flag = 0
    for i in range(0,len(ip)):
        if ip[i] == line:
            count[i] += 1
            flag = 1
    if flag == 0:
        ip.append(line)

for i in range(0,len(count)):
    for j in range(0,len(count)-1):
        if count[j] < count[j+1]:
            temp = count[j+1]
            count[j+1] = count[j]
            count[j] = temp
            temp2 = ip[j+1]
            ip[j+1] = ip[j]
            ip[j] = temp2

for i in range(0,30):
    os.system('nslookup %s'%ip[i])
```

得到结果，最后测试时，成功提交flag，提交格式：scan-42.security.ipip.net

![image-20190729112507523](https://user-images.githubusercontent.com/38073810/62021851-024d3500-b1fc-11e9-91af-922e1ff861c3.png)

没仔细审题，后来发现是对西门子私有通信协议扫描最多的，应该直接提取扫描最多的ip，这样最终就容易判断flag了。

## 1.6.隐信道数据安全分析 [未解决]

题目：安全分析人员截获间谍发出的秘密邮件，该邮件只有一个mp3文件，安全人员怀疑间谍通过某种private的方式将信息传递出去，尝试分析该文件，获取藏在文件中的数据？

附件下载：[1.6.隐信道数据安全分析](https://www.lanzous.com/b864355
)

## 1.7.工业网络设备逆向 [未解决]

题目：这是一个工业系统中使用的路由器，系统的tddp协议存在远程代码执行漏洞。 请找出并分析tddp协议的执行过程，并回答以下问题 1.远程执行命令的消息类型为？（格式为CMD_???_???） 2.在tddp协议中第几个字节 = 什么时，可以控制发出远程执行命令的消息（FLAG格式为16进制）

附件下载：[1.7.工业网络设备逆向](https://www.lanzous.com/b864356
)

公告提示：

![image-20190729113128914](https://user-images.githubusercontent.com/38073810/62021864-15600500-b1fc-11e9-9d6f-8a973751013c.png)

## 1.8.二次设备固件逆向

题目：在对电力行业某二次设备进行渗透测试时，通过弱口令telnet服务获取了设备的权限，并提取出了设备固件文件，现在需要从固件中分析出其他默认硬编码密码或厂家后门口令。

附件下载：[1.8.二次设备固件逆向](https://www.lanzous.com/b864357
)

直接放到mac里搜索strings “pass” 命令如下

![A954434307940E23D65F02AA0E280511](https://user-images.githubusercontent.com/38073810/62021891-3b85a500-b1fc-11e9-98d0-9decd3ad31c5.jpg)

找到passWd后用ida打开找到

![0A170A2C2652160258A9E50F92B18F22](https://user-images.githubusercontent.com/38073810/62021907-4b9d8480-b1fc-11e9-8997-940772781074.jpg)

得到弱口令：icspwd，flag提交格式：icspwd

这题是[Snake](https://bufsnake.github.io/)做的，上面几题也帮我不少(逃。

## 1.9.组态工程逆向分析 [未解决]

题目：很多工业组态软件并未进行安全测试，存在很多安全隐患。请分析组态工程的文件，发现该工程的异常，并获取FLAG。

附件下载：[1.9.组态工程逆向分析（未解决）](https://www.lanzous.com/b864358
)

## 1.10.工业数据库安全分析 [未解决 ，未做]

题目：InSQL是世界上第一种面向工厂的高性能的实时关系型数据库。请分析数据库源文件，获取数据库中的异常，并找到FLAG。

附件下载：[1.10.工业数据库安全分析（未解决）](https://www.lanzous.com/b864359
)

## ## 1.11.工业网络渗透测试 [场景题，未做]

题目：通过VPN接入工业网络靶场场景中，探测发现工业管理网络中的Web应用，通过漏洞控制服务器权限，进而进一步针对工业网络进行渗透。远程VPN地址会通过系统消息发送，请留意。

公告消息：

![image-20190729121207317](https://user-images.githubusercontent.com/38073810/62021914-59eba080-b1fc-11e9-9d25-8f2574ca5f17.png)

## 1.12.SCADA系统渗透测试 [场景题，未做]

题目：当你进入了企业管理网络，可以尝试进入生产管理网络，进而针对未进行安全防护的工业SCADA系统进行渗透测试。尝试发现SCADA系统并测试发现隐藏在系统服务中的Flag。需要通过VPN账号接入远程场景环境，并获取已经获取到访问生产管理网权限。

公告消息：

![image-20190729121207317](https://user-images.githubusercontent.com/38073810/62021914-59eba080-b1fc-11e9-9d25-8f2574ca5f17.png)
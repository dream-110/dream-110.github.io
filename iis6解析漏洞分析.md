来自于：

https://www.cnblogs.com/l1pe1/p/9210094.html

概括: 从技术角度分析IIS6文件名解析漏洞的原理与IIS7的相关情况。

a.IIS6错误解析文件类型现象

1、当WEB目录下，文件名以 xxx.asp;xxx.xxx 来进行命名的时候，此文件将送交asp.dll解析(也就是执行脚本)

2、当WEB目录下，在访问以 xxx.asp 命名的目录下的任意文件时，此文件将送交asp.dll解析(也就是执行脚本)

通过对IIS6的核心文件类型解析相关文件的逆向后，整理出下面的核心处理代码。

[![复制代码](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/copycode.gif)](javascript:void(0);)

```
 1 //reverse code by golds7n with ida
 2 int __thiscall Url(void *this, char *UrlStruct)
 3 {
 4   void *pW3_URL_INFO; // esi@1
 5   int bSuccess; // eax@1
 6   const wchar_t *i; // eax@2
 7   wchar_t *wcsSlashTemp; // ebx@6
 8   int wcsTemp; // eax@6
 9   int wcs_Exten; // eax@6
10   int v8; // esi@9
11   int v10; // eax@11
12   int v11; // ST04_4@13
13   int v12; // eax@13
14   int ExtenDll; // eax@19
15   int Extenisa; // eax@20
16   int ExtenExe; // eax@21
17   int ExtenCgi; // eax@22
18   int ExtenCom; // eax@23
19   int ExtenMap; // eax@24
20   int Entry; // [sp+Ch] [bp-148h]@6
21   wchar_t *wcsMaohaoTemp; // [sp+10h] [bp-144h]@6
22   unsigned int dotCount; // [sp+14h] [bp-140h]@1
23   wchar_t *Str; // [sp+18h] [bp-13Ch]@3
24   char *url_FileName; // [sp+1Ch] [bp-138h]@1
25   char Url_FileExtenName; // [sp+20h] [bp-134h]@1
26   char v25; // [sp+50h] [bp-104h]@1
27 
28  dotCount = 0;
29   pW3_URL_INFO = this;
30   STRU::STRU(&Url_FileExtenName, &v25, 0x100u);
31   url_FileName = (char *)pW3_URL_INFO + 228;
32   bSuccess = STRU::Copy((char *)pW3_URL_INFO + 228, UrlStruct);
33   if ( bSuccess < 0 )
34     goto SubEnd;
35   for ( i = (const wchar_t *)STRU::QueryStr((char *)pW3_URL_INFO + 228); ; i = Str + 1 )
36   {
37     Str = _wcschr(i, '.');   ***********N1************
38     if ( !Str )
39       break;
40     ++dotCount;
41     if ( dotCount > W3_URL_INFO::sm_cMaxDots )
42       break;
43     bSuccess = STRU::Copy(&Url_FileExtenName, Str);
44     if ( bSuccess < 0 )
45       goto SubEnd;
46     wcsSlashTemp = _wcschr(Str, '/'); ***********N2************
47     JUMPOUT(wcsSlashTemp, 0, loc_5A63FD37);
48     wcsTemp = STRU::QueryStr(&Url_FileExtenName);
49     wcsMaohaoTemp = _wcschr((const wchar_t *)wcsTemp, ':');  ***********N3************
50     JUMPOUT(wcsMaohaoTemp, 0, loc_5A63FD51);
51     wcs_Exten = STRU::QueryStr(&Url_FileExtenName);
52     __wcslwr((wchar_t *)wcs_Exten);
53     if ( META_SCRIPT_MAP::FindEntry(&Url_FileExtenName, &Entry) )
54     {
55       *((_DWORD *)pW3_URL_INFO + 201) = Entry;
56       JUMPOUT(wcsSlashTemp, 0, loc_5A63FDAD);
57       STRU::Reset((char *)pW3_URL_INFO + 404);
58       break;
59     }
60     if ( STRU::QueryCCH(&Url_FileExtenName) == 4 )
61     {
62       ExtenDll = STRU::QueryStr(&Url_FileExtenName);
63       if ( !_wcscmp(L".dll", (const wchar_t *)ExtenDll)
64         || (Extenisa = STRU::QueryStr(&Url_FileExtenName), !_wcscmp(L".isa", (const wchar_t *)Extenisa)) )
65         JUMPOUT(loc_5A63FD89);
66       ExtenExe = STRU::QueryStr(&Url_FileExtenName);
67       if ( !_wcscmp(L".exe", (const wchar_t *)ExtenExe)
68         || (ExtenCgi = STRU::QueryStr(&Url_FileExtenName), !_wcscmp(L".cgi", (const wchar_t *)ExtenCgi))
69         || (ExtenCom = STRU::QueryStr(&Url_FileExtenName), !_wcscmp(L".com", (const wchar_t *)ExtenCom)) )
70         JUMPOUT(loc_5A63FD89);
71       ExtenMap = STRU::QueryStr(&Url_FileExtenName);
72       JUMPOUT(_wcscmp(L".map", (const wchar_t *)ExtenMap), 0, loc_5A63FD7B);
73     }
74   }
75   if ( *((_DWORD *)pW3_URL_INFO + 201)
76     || (v10 = *((_DWORD *)pW3_URL_INFO + 202), v10 == 3)
77     || v10 == 2
78     || (v11 = *(_DWORD *)(*((_DWORD *)pW3_URL_INFO + 204) + 0xC4C),
79         v12 = STRU::QueryStr(url_FileName),
80         bSuccess = SelectMimeMappingForFileExt(v12, v11, (char *)pW3_URL_INFO + 756, (char *)pW3_URL_INFO + 1012),
81         bSuccess >= 0) )
82     v8 = 0;
83   else
84 SubEnd:
85     v8 = bSuccess;
86   STRU::_STRU(&Url_FileExtenName);
87   return v8;
88 }
```

[![复制代码](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/copycode.gif)](javascript:void(0);)

上述代码中，作星号标记的是N1,N2,N3，分别检测点号,反斜杠和分号。

大概流程为:

请求 /aaa.asp;xxxx.jpg

N1:从头部查找查找 "."号,获得 .asp;xxxx.jpg

N2:查找";"号,如果有则内存截断

N3:查找"/",如果有则内存截断

最终,将保留下来 .asp 字符串,从META_SCRIPT_MAP脚本映射表里与扩展名匹配对比,并反馈给了asp.dll处理

 

b.IIS7是否延续了漏洞

IIS7的核心处理代码：

[![复制代码](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/copycode.gif)](javascript:void(0);)

```
  1 //reverse code by golds7n with ida
  2 const unsigned __int16 *__stdcall MatchPathInUrl(const unsigned __int16 *url_User, unsigned __int32 url_Length, const unsigned __int16 *IIS_MAP_Wizard)
  3 {
  4   const unsigned __int16 *p; // ebx@1
  5   const unsigned __int16 *pUrl; // ecx@4
  6   const wchar_t *i; // edi@6
  7   signed int isXingHao; // edx@8
  8   const unsigned __int16 cWizard; // ax@10
  9   const unsigned __int16 *pWizard; // esi@11
 10   int cTemp; // eax@17
 11   int pCharTemp; // esi@23
 12   const unsigned __int16 *pCharUser; // eax@43
 13   const unsigned __int16 byteChar; // cx@44
 14   const wchar_t cSlash; // ax@50
 15   const unsigned __int16 *Str2; // [sp+8h] [bp-8h]@11
 16   signed int bFound; // [sp+Ch] [bp-4h]@3
 17 
 18  p = IIS_MAP_Wizard;
 19   if ( *IIS_MAP_Wizard != '*' || IIS_MAP_Wizard[1] )
 20   {
 21     bFound = 1;
 22     if ( *IIS_MAP_Wizard == '/' )
 23     {
 24       p = IIS_MAP_Wizard + 1;
 25       bFound = 0;
 26       ++IIS_MAP_Wizard;
 27     }
 28     pUrl = url_User;
 29     if ( *url_User == '/' )
 30     {
 31       pUrl = url_User + 1;
 32       ++url_User;
 33     }
 34 LABEL_6:
 35     for ( i = pUrl; ; i += pCharTemp )
 36     {
 37       while ( *p == '?' )
 38       {
 39         if ( !*i )
 40           return 0;
 41         if ( *i == '/' )
 42           goto LABEL_30;
 43         ++p;
 44         ++i;
 45       }
 46       isXingHao = 0;
 47       if ( *p == '*' )
 48       {
 49         ++p;
 50         isXingHao = 1;
 51       }
 52       cWizard = *p;
 53       if ( !*p )
 54         break;
 55       pWizard = p;
 56       Str2 = p;
 57       if ( cWizard != '*' )
 58       {
 59         do
 60         {
 61           if ( cWizard == '?' )
 62             break;
 63           if ( !cWizard )
 64             break;
 65           ++pWizard;
 66           cWizard = *pWizard;
 67           Str2 = pWizard;
 68         }
 69         while ( *pWizard != '*' );
 70       }
 71       if ( isXingHao )
 72       {
 73         if ( !*pWizard )
 74         {
 75           cTemp = (int)&i[pWizard - p];
 76           if ( cTemp > (unsigned int)&pUrl[url_Length] )
 77             return 0;
 78           while ( *(_WORD *)cTemp != '/' && *(_WORD *)cTemp && *i != '/' && *i )
 79           {
 80             ++i;
 81             cTemp += 2;
 82           }
 83         }
 84         pCharTemp = pWizard - p;
 85         while ( _wcsncmp(i, p, pCharTemp) )
 86         {
 87           if ( !*i )
 88             return 0;
 89           if ( *i == '/' )
 90             goto LABEL_29;
 91           ++i;
 92         }
 93       }
 94       else
 95       {
 96         pCharTemp = pWizard - p;
 97         if ( _wcsncmp(i, p, pCharTemp) )
 98         {
 99 LABEL_29:
100           pUrl = url_User;
101 LABEL_30:
102           if ( !bFound )
103             return 0;
104           while ( *pUrl != '/' )
105           {
106             if ( !*pUrl )
107               return 0;
108             ++pUrl;
109           }
110           if ( !*pUrl )
111             return 0;
112           p = IIS_MAP_Wizard;
113           ++pUrl;
114           url_User = pUrl;
115           goto LABEL_6;
116         }
117       }
118       p = Str2;
119       pUrl = url_User;
120     }
121     if ( isXingHao )
122     {
123       cSlash = *i;
124       if ( *i == '/' )
125         return i;
126       do
127       {
128         if ( !cSlash )
129           break;
130         ++i;
131         cSlash = *i;
132       }
133       while ( *i != '/' );
134     }
135     if ( *i != '/' && *i )
136       goto LABEL_30;
137     return i;
138   }
139   pCharUser = url_User;
140   do
141   {
142     byteChar = *pCharUser;
143     ++pCharUser;
144   }
145   while ( byteChar );
146   return &url_User[pCharUser - (url_User + 1)];
147 }
148 MatchPathInUrl(const unsigned __int16 *url_User, unsigned __int32 url_Length, const unsigned __int16 *IIS_MAP_Wizard)
```

[![复制代码](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/copycode.gif)](javascript:void(0);)

参数url_User是用户提交的路径参数,类似PHOST/DEFAULT WEB SITE/aa.asp;xxx.jpg,由 服务/站点名称/请求路径 构成,IIS_MAP_Wizard是在管理器文件映射里的每个表项,譬如*.ASP

比较的结果就是,拿aa.asp;xxx.jpg与*.ASP进行匹配,显然结果是不匹配的(/xxx.asp/xxx.jpg,是拿xxx.jpg和*.ASP进行匹配)

c.总结

IIS6文件映射配置图

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/iis6-2.jpg)
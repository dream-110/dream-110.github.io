来自于：

https://www.freebuf.com/articles/web/192063.html

Web中间件常见漏洞总结

[ningjing ](https://www.freebuf.com/author/ningjing)2019-02-22 09:00:58 2241468 11

***本文中涉及到的相关漏洞已报送厂商并得到修复，本文仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担。**

***本文作者：ningjing，本文属 FreeBuf 原创奖励计划，未经许可禁止转载。**

## 一、 常见web中间件及其漏洞概述

### （一） IIS

1、PUT漏洞

2、短文件名猜解

3、远程代码执行

4、解析漏洞

### （二） Apache

1、解析漏洞

2、目录遍历

### （三） Nginx

1、文件解析

2、目录遍历

3、CRLF注入

4、目录穿越

### （四）Tomcat

1、远程代码执行

2、war后门文件部署

### （五）jBoss

1、反序列化漏洞

2、war后门文件部署

### （六）WebLogic

1、反序列化漏洞

2、SSRF

3、任意文件上传

4、war后门文件部署

### （七）其它中间件相关漏洞

1、FastCGI未授权访问、任意命令执行

2、PHPCGI远程代码执行

## 二、 IIS漏洞分析

### （一） IIS简介

IIS是Internet Information Services的缩写，意为互联网信息服务，是由微软公司提供的基于运行Microsoft Windows的互联网基本服务。最初是Windows NT版本的可选包，随后内置在Windows 2000、Windows XP Professional和Windows Server 2003一起发行，但在Windows XP Home版本上并没有IIS。IIS是一种Web（网页）服务组件，其中包括Web服务器、FTP服务器、NNTP服务器和SMTP服务器，分别用于网页浏览、文件传输、新闻服务和邮件发送等方面，它使得在网络（包括互联网和局域网）上发布信息成了一件很容易的事。

IIS的安全脆弱性曾长时间被业内诟病，一旦IIS出现远程执行漏洞威胁将会非常严重。远程执行代码漏洞存在于 HTTP 协议堆栈 (HTTP.sys) 中，当 HTTP.sys 未正确分析经特殊设计的 HTTP 请求时会导致此漏洞。成功利用此漏洞的攻击者可以在系统帐户的上下文中执行任意代码，可以导致IIS服务器所在机器蓝屏或读取其内存中的机密数据

### （二） PUT漏洞

**1、漏洞介绍及成因**

IIS Server 在 Web 服务扩展中开启了 WebDAV ，配置了可以写入的权限，造成任意文件上传。

版本： IIS6.0

**2、漏洞复现**

1） 开启WebDAV 和写权限

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954468_5c162264b3e77.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954489_5c16227975735.png!small)

2） 利用burp测试

抓包，将GET请求改为OPTIONS

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954500_5c162284754a0.png!small)

3）利用工具进行测试

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954508_5c16228cd082b.png!small)

成功上传，再上传一句话木马，然后用菜刀连接，getshell

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954522_5c16229a1787c.png!small)

**3、漏洞修复**

关闭WebDAV 和写权限

### （二）短文件名猜解

**1、漏洞介绍及成因**

IIS的短文件名机制，可以暴力猜解短文件名，访问构造的某个存在的短文件名，会返回404，访问构造的某个不存在的短文件名，返回400。

**2、漏洞复现**

1）、在网站根目录下添加aaaaaaaaaa.html文件

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954542_5c1622ae9bc64.png!small)

3） 进行猜解

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954552_5c1622b8d255e.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954584_5c1622d80a9c8.png!small)

**3、漏洞修复**

修复方法：

1）升级.net framework

2）修改注册表禁用短文件名功能

快捷键Win+R打开命令窗口，输入regedit打开注册表窗口，找到路径：

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem，将其中的 NtfsDisable8dot3NameCreation这一项的值设为 1，1代表不创建短文件名格式，修改完成后，需要重启系统生效

3）CMD关闭NTFS 8.3文件格式的支持

4）将web文件夹的内容拷贝到另一个位置，如c:\www到d:\w,然后删除原文件夹，再重命名d:\w到c:\www。

修复后：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954597_5c1622e59d557.png!small)

**4、局限性**

\1) 此漏洞只能确定前6个字符，如果后面的字符太长、包含特殊字符，很难猜解；

\2) 如果文件名本身太短（无短文件名）也是无法猜解的；

\3) 如果文件名前6位带空格，8.3格式的短文件名会补进，和真实文件名不匹配；

### （三） 远程代码执行

**1、 漏洞介绍及成因**

在IIS6.0处理PROPFIND指令的时候，由于对url的长度没有进行有效的长度控制和检查，导致执行memcpy对虚拟路径进行构造的时候，引发栈溢出，从而导致远程代码执行。

**2、 漏洞复现**

1）漏洞环境搭建

在windows server 2003 r2 32位上安装iis6.0

2） 触发漏洞

在本地执行exp，exp如下

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954632_5c1623084ecaa.png!small)

执行成功后，服务器端弹出计算器：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954644_5c162314621a4.png!small)

**3、 漏洞修复**

1）关闭 WebDAV 服务

2） 使用相关防护设备

### （四） 解析漏洞

**1、 漏洞介绍及成因**

IIS 6.0 在处理含有特殊符号的文件路径时会出现逻辑错误，从而造成文件解析漏洞。这一漏洞有两种完全不同的利用方式：

```
/test.asp/test.jpgtest.asp;.jpg
```

**2、漏洞复现**

利用方式 1

第一种是新建一个名为 "test.asp" 的目录，该目录中的任何文件都被 IIS 当作 asp 程序执行（特殊符号是 “/” ）

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954672_5c162330306e1.png!small)

利用方式 2

第二种是上传名为 "test.asp;.jpg" 的文件，虽然该文件真正的后缀名是 ".jpg", 但由于含有特殊符号 ";" ，仍会被 IIS 当做 asp 程序执行

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954681_5c162339092fb.png!small)

IIS7.5 文件解析漏洞

```
test.jpg/.php
```

URL 中文件后缀是 .php ，便无论该文件是否存在，都直接交给 php 处理，而 php 又默认开启 "cgi.fix_pathinfo", 会对文件进行 “ 修理 ” ，可谓 “ 修理 ” ？举个例子，当 php 遇到路径 "/aaa.xxx/bbb.yyy" 时，若 "/aaa.xxx/bbb.yyy" 不存在，则会去掉最后的 “bbb.yyy" ，然后判断 "/aaa.xxx" 是否存在，若存在，则把 “/aaa.xxx" 当作文件。

若有文件 test.jpg ，访问时在其后加 /.php ，便可以把 "test.jpg/.php" 交给 php ， php 修理文件路径 "test.jpg/.php" 得到 ”test.jpg" ，该文件存在，便把该文件作为 php 程序执行了。

**3、 漏洞修复**

1）对新建目录文件名进行过滤，不允许新建包含‘.’的文件

2）曲线网站后台新建目录的功能，不允许新建目录

3）限制上传的脚本执行权限，不允许执行脚本

4）过滤.asp/xm.jpg，通过ISApi组件过滤

## 三、 Apache漏洞分析

### （一） Apache简介

Apache 是世界使用排名第一的Web 服务器软件。它可以运行在几乎所有广泛使用的 计算机平台上，由于其 跨平台 和安全性被广泛使用，是最流行的Web服务器端软件之一。它快速、可靠并且可通过简单的API扩充，将 Perl/ Python等 解释器编译到服务器中。

### （二） 解析漏洞

**1、 漏洞介绍及成因**

Apache文件解析漏洞与用户的配置有密切关系，严格来说属于用户配置问题。

Apache文件解析漏洞涉及到一个解析文件的特性：

Apache默认一个文件可以有多个以点分隔的后缀，当右边的后缀无法识别（不在mime.tyoes内），则继续向左识别，当我们请求这样一个文件：shell.xxx.yyy

```
yyy->无法识别，向左xxx->无法识别，向左
```

php->发现后缀是php，交给php处理这个文件

**2、 漏洞复现**

上传一个后缀名为360的php文件

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954824_5c1623c8ad26c.png!small)

**3、 漏洞修复**

将AddHandler application/x-httpd-php .php的配置文件删除。

### （三） 目录遍历

**1、 漏洞介绍及成因**

由于配置错误导致的目录遍历

**2、 漏洞复现**

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954845_5c1623dd062fa.png!small)

**3、 漏洞修复**

修改apache配置文件httpd.conf

找到Options+Indexes+FollowSymLinks +ExecCGI并修改成 Options-Indexes+FollowSymLinks +ExecCGI 并保存；

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954862_5c1623eee9f99.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954870_5c1623f62f920.png!small)

## 四、 Nginx漏洞分析

### （一） Nginx简介

Nginx 是一款 轻量级的 Web 服务器、 反向代理 服务器及 电子邮件（IMAP/POP3）代理服务器，并在一个BSD-like 协议下发行。其特点是占有内存少， 并发能力强，事实上nginx的并发能力确实在同类型的网页服务器中表现较好

### （二）文件解析

**1、 漏洞介绍及成因**

对任意文件名，在后面添加/任意文件名.php的解析漏洞，比如原本文件名是test.jpg，可以添加test.jpg/x.php进行解析攻击。

**2、 漏洞复现**

在网站根目录下新建一个i.gif的文件，在里面写入phpinfo()

在浏览器中打开

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954886_5c162406b3984.png!small)

利用文件解析漏洞，输入192.168.139.129:100/i.gif.2.php,发现无法解析

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954897_5c162411a7874.png!small)

将/etc/php5/fpm/pool.d/[www.conf](http://www.conf/)中security.limit_extensions = .php中的.php删除

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954906_5c16241ae051f.png!small)

再次在浏览器中打开，成功解析

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954915_5c162423d8916.png!small)

**3、 漏洞修复**

1） 将php.ini文件中的cgi.fix_pathinfo的值设为0.这样php在解析1.php/1.jpg这样的目录时，只要1.jpg不存在就会显示404；

2） 将/etc/php5/fpm/pool.d/[www.conf](http://www.conf/)中security.limit_ectensions后面的值设为.php

### （三）目录遍历

**1、 漏洞简介及成因**

Nginx的目录遍历与Apache一样，属于配置方面的问题，错误的配置可到导致目录遍历与源码泄露‘

**2、 漏洞复现**

打开test目录，发现无法打开

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954939_5c16243b564a5.png!small)

修改/etc/nginx/sites-avaliable/default，在如下图所示的位置添加autoindex on

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954951_5c1624474d49a.png!small)

再次访问

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954962_5c162452ad7b8.png!small)

**3、 漏洞修复**

将/etc/nginx/sites-avaliable/default里的autoindex on改为autoindex off

### （四） CRLF注入

**1、 漏洞简介及成因**

CRLF时“回车+换行”（\r\n）的简称。

HTTP Header与HTTP Body时用两个CRLF分隔的，浏览器根据两个CRLF来取出HTTP内容并显示出来。

通过控制HTTP消息头中的字符，注入一些恶意的换行，就能注入一些会话cookie或者html代码，由于Nginx配置不正确，导致注入的代码会被执行。

**2、 漏洞复现**

访问页面，抓包

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544954974_5c16245ee78f0.png!small)

由于页面重定向，并没有弹窗。

**3、 漏洞修复**

Nginx的配置文件/etc/nginx/conf.d/error1.conf修改为使用不解码的url跳转。

### （五） 目录穿越

**1、 漏洞简介及成因**

Nginx反向代理，静态文件存储在/home/下，而访问时需要在url中输入files，配置文件中/files没有用/闭合，导致可以穿越至上层目录。

**2、 漏洞复现**

访问：http://192.168.139.128:8081/files/

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955023_5c16248f1b4df.png!small)

访问：http://192.168.139.128:8081/files../

成功实现目录穿越：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955058_5c1624b2016aa.png!small)

**3、 漏洞修复**

Nginx的配置文件/etc/nginx/conf.d/error2.conf的/files使用/闭合。

## 五、 Tomcat漏洞分析

### （一） Tomcat简介

Tomcat 服务器是一个免费的开放源代码的Web 应用服务器，属于轻量级应用 服务器，在中小型系统和并发访问用户不是很多的场合下被普遍使用，是开发和调试JSP 程序的首选。对于一个初学者来说，可以这样认为，当在一台机器上配置好Apache 服务器，可利用它响应 HTML （ 标准通用标记语言下的一个应用）页面的访问请求。实际上Tomcat是Apache 服务器的扩展，但运行时它是独立运行的，所以当运行tomcat 时，它实际上作为一个与Apache 独立的进程单独运行的。

### （二） 远程代码执行

**1、 漏洞简介及成因**

Tomcat 运行在Windows 主机上，且启用了 HTTP PUT 请求方法，可通过构造的攻击请求向服务器上传包含任意代码的 JSP 文件，造成任意代码执行。

影响版本： Apache Tomcat 7.0.0 – 7.0.81

**2、 漏洞复现**

配置漏洞，开启put方法可上传文件功能。

tomcat文件夹下的/conf/web.xml文件插入：

```
     <init-param>           <param-name>readonly</param-name>           <param-value>false</param-value>     </init-param>
```

重启tomcat服务。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955083_5c1624cb8ac8a.png!small)

访问127.0.0.1：8080，burp抓包，send to Repeater，将请求方式改为PUT，创建一个122.jsp，并用%20转义空格字符。123.jsp内容为：

```
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

返回201，说明创建成功。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955095_5c1624d7b5447.png!small)

访问127.0.0.1：8080/122.jsp?cmd=calc。

弹出计算器：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955107_5c1624e39d5ed.png!small)

**3、 漏洞修复**

1）检测当前版本是否在影响范围内，并禁用PUT方法。

2）更新并升级至最新版。

### （三）war后门文件部署

**1、漏洞简介及成因**

Tomcat 支持在后台部署war文件，可以直接将webshell部署到web目录下。

若后台管理页面存在弱口令，则可以通过爆破获取密码。

**2、漏洞复现**

Tomcat安装目录下conf里的tomcat-users.xml配置如下：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955120_5c1624f0e6795.png!small)

访问后台，登陆：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955131_5c1624fb87534.png!small)

上传一个war包，里面是jsp后门：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955146_5c16250a9c859.png!small)

成功上传并解析，打开：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955158_5c162516bfdc4.png!small)

可执行系统命令：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955173_5c162525a51ea.png!small)

也可进行文件管理，任意查看、删除、上传文件：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955183_5c16252f655db.png!small)

**3、漏洞修复**

1）在系统上以低权限运行Tomcat应用程序。创建一个专门的 Tomcat服务用户，该用户只能拥有一组最小权限（例如不允许远程登录）。

2）增加对于本地和基于证书的身份验证，部署账户锁定机制（对于集中式认证，目录服务也要做相应配置）。在CATALINA_HOME/conf/web.xml文件设置锁定机制和时间超时限制。

3）以及针对manager-gui/manager-status/manager-script等目录页面设置最小权限访问限制。

4）后台管理避免弱口令。

## 六、 jBoss漏洞分析

### （一） jBoss简介

jBoss是一个基于J2EE的开发源代码的应用服务器。 JBoss代码遵循LGPL许可，可以在任何商业应用中免费使用。JBoss是一个管理EJB的容器和服务器，支持EJB1.1、EJB 2.0和EJB3的规范。但JBoss核心服务不包括支持servlet/JSP的WEB容器，一般与Tomcat或Jetty绑定使用。

### （二） 反序列化漏洞

**1、 漏洞介绍及成因**

Java序列化，简而言之就是把java对象转化为字节序列的过程。而反序列话则是再把字节序列恢复为java对象的过程，然而就在这一转一变得过程中，程序员的过滤不严格，就可以导致恶意构造的代码的实现。

**2、 漏洞复现**

靶机启动jboss。

攻击机访问靶机服务：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955201_5c16254132af8.png!small)

访问/invoker/readonly。

返回500，说明页面存在，此页面有反序列化漏洞：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955212_5c16254c54a5e.png!small)

抓包：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955225_5c162559c837c.png!small)

改包。

POST payload.bin中数据。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955253_5c162575ce0a6.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955240_5c162568b8024.png!small)

查看靶机，弹出计算器。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955250_5c1625722d41e.png!small)

**3、 漏洞修复**

有效解决方案：升级到JBOSS AS7版本临时解决方案：

1）不需要http-invoker.sar 组件的用户可直接删除此组件；

2）用于对 httpinvoker 组件进行访问控制。

### （三） war后门文件部署

**1、 漏洞介绍及成因**

jBoss后台管理页面存在弱口令，通过爆破获得账号密码。登陆后台上传包含后门的war包。

**2、 漏洞复现**

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955269_5c16258565dca.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955275_5c16258b733e0.png!small)

点击Web Application(war)s。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955283_5c16259340980.png!small)

点击add a new resource。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955291_5c16259b4b362.png!small)

选择一个war包上传，上传后，进入该war包，点击start。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955300_5c1625a46f26a.png!small)

查看status为sucessful。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955310_5c1625ae165ad.png!small)

访问该war包页面，进入后门。

可进行文件管理和系统命令执行。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955318_5c1625b6d0f4c.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955328_5c1625c0579fd.png!small)

## 七、 WebLogic漏洞分析

### （一） WebLogic简介

WebLogic是美国Oracle公司出品的一个applicationserver，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。

### （二） 反序列化漏洞

**1、 漏洞简介及成因**

Java序列化，简而言之就是把java对象转化为字节序列的过程。而反序列话则是再把字节序列恢复为java对象的过程，然而就在这一转一变得过程中，程序员的过滤不严格，就可以导致恶意构造的代码的实现。

**2、漏洞复现**

使用vulhub实验环境，启动实验环境，访问靶机，抓包，修改数据包。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955349_5c1625d5f0cfb.png!small)

Kali启动监听。

发送数据包成功后，拿到shell。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955361_5c1625e14f776.png!small)

**3、漏洞修复**

1）升级Oracle 10月份补丁。

2）对访问wls-wsat的资源进行访问控制。

### （三） SSRF

**1、 漏洞简介及成因**

Weblogic 中存在一个SSRF漏洞，利用该漏洞可以发送任意HTTP请求，进而攻击内网中redis、fastcgi等脆弱组件。

**2、 漏洞复现**

使用vulhub实验环境，启动环境。

访问http://192.168.139.129:7001/uddiexplorer/SearchPublicRegistries.jsp。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955373_5c1625edf3c4f.png!small)

用burp抓包，修改请求。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955383_5c1625f70b11d.png!small)

启动nc监听2222端口。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955390_5c1625febc7e3.png!small)

拿到shell。

**3、 漏洞修复**

方法一：

以修复的直接方法是将SearchPublicRegistries.jsp直接删除就好了；

方法二：

1）删除uddiexplorer文件夹

2）限制uddiexplorer应用只能内网访问

方法三：（常用）

Weblogic服务端请求伪造漏洞出现在uddi组件（所以安装Weblogic时如果没有选择uddi组件那么就不会有该漏洞），更准确地说是uudi包实现包uddiexplorer.war下的SearchPublicRegistries.jsp。方法二采用的是改后辍的方式，修复步骤如下：

1）将weblogic安装目录下的wlserver_10.3/server/lib/uddiexplorer.war做好备份

2）将weblogic安装目录下的server/lib/uddiexplorer.war下载

3）用winrar等工具打开uddiexplorer.war

4)将其下的SearchPublicRegistries.jsp重命名为SearchPublicRegistries.jspx

5）保存后上传回服务端替换原先的uddiexplorer.war

6）对于多台主机组成的集群，针对每台主机都要做这样的操作

7）由于每个server的tmp目录下都有缓存所以修改后要彻底重启weblogic（即停应用--停server--停控制台--启控制台--启server--启应用）

### （四） 任意文件上传

**1、 漏洞简介及成因**

通过访问config.do配置页面，先更改Work Home工作目录，用有效的已部署的Web应用目录替换默认的存储JKS Keystores文件的目录，之后使用"添加Keystore设置"的功能，可上传恶意的JSP脚本文件。

**2、 漏洞复现**

访问http://192.168.139.129:7001/ws_utc/config.do。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955408_5c162610d485e.png!small)

设置Work Home Dir为`/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css`。

然后点击安全 -> 增加，然后上传 webshell ，这里我上传一个 jsp 大马。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955420_5c16261c14846.png!small)

上传后，查看返回的数据包，其中有时间戳：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955428_5c16262471d61.png!small)

可以看到时间戳为1543145154632。

访问http://192.168.139.129:7001/ws_utc/css/config/keystore/1543145154632_lele.jsp。

可以进行文件管理、文件上传、系统命令执行等。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955438_5c16262ed74a2.png!small)

尝试以下执行系统命令。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955446_5c16263615970.png!small)

命令执行成功。

**3、 漏洞修复**

方案1：

使用Oracle官方通告中的补丁链接：

http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html

https://support.oracle.com/rs?type=doc&id=2394520.1

方案2:

1）进入Weblogic Server管理控制台；

2）domain设置中，启用”生产模式”。

### （五） war后门文件部署

**1、 漏洞简介及成因**

由于WebLogic后台存在弱口令，可直接登陆后台上传包含后门的war包。

**2、 漏洞复现**

访问http://192.168.139.129:7001/console

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955458_5c162642c59ac.png!small)

使用弱口令登陆至后台。

点击锁定并编辑。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955467_5c16264b0e5ed.png!small)

选择部署，进一步点击右边的安装。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955476_5c162654ad096.png!small)

点击上传文件 -- 进入文件上传界面，选择要上传的 war 包。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955485_5c16265d47acf.png!small)

进入下一步，选择对应的 war 包进行部署，下一步下一步直至完成。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955495_5c16266778cf9.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955518_5c16267e4cdda.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955523_5c1626831e3b3.png!small)

点击激活更改。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955531_5c16268b6846b.png!small)

启动上传的 war 包所生成的服务。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955539_5c16269393d67.png!small)

拿到 webshell。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955547_5c16269badc78.png!small)

**3、 漏洞修复**

防火墙设置端口过滤，也可以设置只允许访问后台的IP列表，避免后台弱口令。

## 八、 其它中间件相关漏洞

### （一） FastCGI未授权访问、任意命令执行

**1、 漏洞简介及成因**

服务端使用fastcgi协议并对外网开放9000端口，可以构造fastcgi协议包内容，实现未授权访问服务端.php文件以及执行任意命令。

**2、 漏洞复现**

使用vulhub实验环境，启动实验环境。

在攻击机使用命令python fpm.py 192.168.237.136 /etc/passwd，观察返回结果。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955569_5c1626b181057.png!small)

由于访问非*.PHP文件，所以返回结果403。

使用命令执行一个默认存在的 php 文件。

```
python fpm.py 192.168.237.136 /usr/local/lib/php/PEAR.php
```

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955581_5c1626bd94566.png!small)

利用命令进行任意命令执行复现。

```
python fpm.py 192.168.139.129 /usr/local/lib/php/PEAR.php-c '<?php echo `pwd`; ?>'python fpm.py 192.168.139.129 /usr/local/lib/php/PEAR.php-c '<?php echo `ifconfig`; ?>'python fpm.py 192.168.139.129 /usr/local/lib/php/PEAR.php-c '<?php echo `ls`; ?>'
```

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955594_5c1626ca98c2c.png!small)

**3、 漏洞修复**

更改默认端口

### （二） PHPCGI远程代码执行

**1、 漏洞简介及成因**

在apache调用php解释器解释.php文件时，会将url参数传我给php解释器，如果在url后加传命令行开关（例如-s、-d 、-c或-dauto_prepend_file%3d/etc/passwd+-n）等参数时，会导致源代码泄露和任意代码执行。

此漏洞影响php-5.3.12以前的版本，mod方式、fpm方式不受影响。

**2、 漏洞复现**

使用vulhub实验环境，启动环境。

访问http://192.168.139.129:8080/index.php。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955605_5c1626d552e60.png!small)

抓包，修改包。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1544955613_5c1626dd7ad9f.png!small)

命令成功执行。

**3、 漏洞修复**

三种方法：

1）升级php版本；（php-5.3.12以上版本）;

2）在apache上做文章，开启url过滤，把危险的命令行参数给过滤掉，由于这种方法修补比较简单，采用比较多吧。

具体做法：

修改http.conf文件，找到<Directory/>增加以下三行

RewriteEngine on

RewriteCond %{QUERY_STRING} ^(%2d|-)[^=]+$ [NC]

RewriteRule ^(.*) $1? [L]

重启一下apache即可，但是要考虑到，相当于每次request就要进行一次url过滤，如果访问量大的话，可能会增加apache的负担。

3）打上php补丁。

补丁下载地址:https://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/
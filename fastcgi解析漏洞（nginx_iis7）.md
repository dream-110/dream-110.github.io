- 来自于

https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html

搭过php相关环境的同学应该对fastcgi不陌生，那么fastcgi究竟是什么东西，为什么nginx可以通过fastcgi来对接php？

## [Fastcgi Record](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#fastcgi-record)

Fastcgi其实是一个通信协议，和HTTP协议一样，都是进行数据交换的一个通道。

HTTP协议是浏览器和服务器中间件进行数据交换的协议，浏览器将HTTP头和HTTP体用某个规则组装成数据包，以TCP的方式发送到服务器中间件，服务器中间件按照规则将数据包解码，并按要求拿到用户需要的数据，再以HTTP协议的规则打包返回给服务器。

类比HTTP协议来说，fastcgi协议则是服务器中间件和某个语言后端进行数据交换的协议。Fastcgi协议由多个record组成，record也有header和body一说，服务器中间件将这二者按照fastcgi的规则封装好发送给语言后端，语言后端解码以后拿到具体数据，进行指定操作，并将结果再按照该协议封装好后返回给服务器中间件。

和HTTP头不同，record的头固定8个字节，body是由头中的contentLength指定，其结构如下：

```
typedef struct {
  /* Header */
  unsigned char version; // 版本
  unsigned char type; // 本次record的类型
  unsigned char requestIdB1; // 本次record对应的请求id
  unsigned char requestIdB0;
  unsigned char contentLengthB1; // body体的大小
  unsigned char contentLengthB0;
  unsigned char paddingLength; // 额外块大小
  unsigned char reserved; 

  /* Body */
  unsigned char contentData[contentLength];
  unsigned char paddingData[paddingLength];
} FCGI_Record;
```

头由8个uchar类型的变量组成，每个变量1字节。其中，`requestId`占两个字节，一个唯一的标志id，以避免多个请求之间的影响；`contentLength`占两个字节，表示body的大小。

语言端解析了fastcgi头以后，拿到`contentLength`，然后再在TCP流里读取大小等于`contentLength`的数据，这就是body体。

Body后面还有一段额外的数据（Padding），其长度由头中的paddingLength指定，起保留作用。不需要该Padding的时候，将其长度设置为0即可。

可见，一个fastcgi record结构最大支持的body大小是`2^16`，也就是65536字节。

## [Fastcgi Type](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#fastcgi-type)

刚才我介绍了fastcgi一个record中各个结构的含义，其中第二个字节`type`我没详说。

`type`就是指定该record的作用。因为fastcgi一个record的大小是有限的，作用也是单一的，所以我们需要在一个TCP流里传输多个record。通过`type`来标志每个record的作用，用`requestId`作为同一次请求的id。

也就是说，每次请求，会有多个record，他们的`requestId`是相同的。

借用[该文章](http://blog.csdn.net/shreck66/article/details/50355729)中的一个表格，列出最主要的几种`type`：

[![14931267923354.jpg](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/e29518b1-3574-426f-b75f-8cabbb89a15a.9efc537226ce.jpg)](https://www.leavesongs.com/media/attachment/2017/04/25/e29518b1-3574-426f-b75f-8cabbb89a15a.jpg)

看了这个表格就很清楚了，服务器中间件和后端语言通信，第一个数据包就是`type`为1的record，后续互相交流，发送`type`为4、5、6、7的record，结束时发送`type`为2、3的record。

当后端语言接收到一个`type`为4的record后，就会把这个record的body按照对应的结构解析成key-value对，这就是环境变量。环境变量的结构如下：

```
typedef struct {
  unsigned char nameLengthB0;  /* nameLengthB0  >> 7 == 0 */
  unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
  unsigned char nameData[nameLength];
  unsigned char valueData[valueLength];
} FCGI_NameValuePair11;

typedef struct {
  unsigned char nameLengthB0;  /* nameLengthB0  >> 7 == 0 */
  unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
  unsigned char valueLengthB2;
  unsigned char valueLengthB1;
  unsigned char valueLengthB0;
  unsigned char nameData[nameLength];
  unsigned char valueData[valueLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
} FCGI_NameValuePair14;

typedef struct {
  unsigned char nameLengthB3;  /* nameLengthB3  >> 7 == 1 */
  unsigned char nameLengthB2;
  unsigned char nameLengthB1;
  unsigned char nameLengthB0;
  unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
  unsigned char nameData[nameLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
  unsigned char valueData[valueLength];
} FCGI_NameValuePair41;

typedef struct {
  unsigned char nameLengthB3;  /* nameLengthB3  >> 7 == 1 */
  unsigned char nameLengthB2;
  unsigned char nameLengthB1;
  unsigned char nameLengthB0;
  unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
  unsigned char valueLengthB2;
  unsigned char valueLengthB1;
  unsigned char valueLengthB0;
  unsigned char nameData[nameLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
  unsigned char valueData[valueLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
} FCGI_NameValuePair44;
```

这其实是4个结构，至于用哪个结构，有如下规则：

1. key、value均小于128字节，用`FCGI_NameValuePair11`
2. key大于128字节，value小于128字节，用`FCGI_NameValuePair41`
3. key小于128字节，value大于128字节，用`FCGI_NameValuePair14`
4. key、value均大于128字节，用`FCGI_NameValuePair44`

为什么我只介绍`type`为4的record？因为环境变量在后面PHP-FPM里有重要作用，之后写代码也会写到这个结构。`type`的其他情况，大家可以自己翻文档理解理解。

## [PHP-FPM（FastCGI进程管理器）](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#php-fpmfastcgi)

那么，PHP-FPM又是什么东西？

FPM其实是一个fastcgi协议解析器，Nginx等服务器中间件将用户请求按照fastcgi的规则打包好通过TCP传给谁？其实就是传给FPM。

FPM按照fastcgi的协议将TCP流解析成真正的数据。

举个例子，用户访问`http://127.0.0.1/index.php?a=1&b=2`，如果web目录是`/var/www/html`，那么Nginx会将这个请求变成如下key-value对：

```
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/index.php',
    'SCRIPT_NAME': '/index.php',
    'QUERY_STRING': '?a=1&b=2',
    'REQUEST_URI': '/index.php?a=1&b=2',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
}
```

这个数组其实就是PHP中`$_SERVER`数组的一部分，也就是PHP里的环境变量。但环境变量的作用不仅是填充`$_SERVER`数组，也是告诉fpm：“我要执行哪个PHP文件”。

PHP-FPM拿到fastcgi的数据包后，进行解析，得到上述这些环境变量。然后，执行`SCRIPT_FILENAME`的值指向的PHP文件，也就是`/var/www/html/index.php`。

## [Nginx（IIS7）解析漏洞](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#nginxiis7)

Nginx和IIS7曾经出现过一个PHP相关的解析漏洞（测试环境`https://github.com/phith0n/vulhub/tree/master/nginx_parsing_vulnerability`），该漏洞现象是，在用户访问`http://127.0.0.1/favicon.ico/.php`时，访问到的文件是favicon.ico，但却按照.php后缀解析了。

用户请求`http://127.0.0.1/favicon.ico/.php`，nginx将会发送如下环境变量到fpm里：

```
{
    ...
    'SCRIPT_FILENAME': '/var/www/html/favicon.ico/.php',
    'SCRIPT_NAME': '/favicon.ico/.php',
    'REQUEST_URI': '/favicon.ico/.php',
    'DOCUMENT_ROOT': '/var/www/html',
    ...
}
```

正常来说，`SCRIPT_FILENAME`的值是一个不存在的文件`/var/www/html/favicon.ico/.php`，是PHP设置中的一个选项`fix_pathinfo`导致了这个漏洞。PHP为了支持Path Info模式而创造了`fix_pathinfo`，在这个选项被打开的情况下，fpm会判断`SCRIPT_FILENAME`是否存在，如果不存在则去掉最后一个`/`及以后的所有内容，再次判断文件是否存在，往次循环，直到文件存在。

所以，第一次fpm发现`/var/www/html/favicon.ico/.php`不存在，则去掉`/.php`，再判断`/var/www/html/favicon.ico`是否存在。显然这个文件是存在的，于是被作为PHP文件执行，导致解析漏洞。

正确的解决方法有两种，一是在Nginx端使用`fastcgi_split_path_info`将path info信息去除后，用tryfiles判断文件是否存在；二是借助PHP-FPM的`security.limit_extensions`配置项，避免其他后缀文件被解析。

## [`security.limit_extensions`配置](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#securitylimit_extensions)

写到这里，PHP-FPM未授权访问漏洞也就呼之欲出了。PHP-FPM默认监听9000端口，如果这个端口暴露在公网，则我们可以自己构造fastcgi协议，和fpm进行通信。

此时，`SCRIPT_FILENAME`的值就格外重要了。因为fpm是根据这个值来执行php文件的，如果这个文件不存在，fpm会直接返回404：

[![14931285844835.jpg](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/703367c4-af98-4702-85f0-794b30776a4f.073e567856db.jpg)](https://www.leavesongs.com/media/attachment/2017/04/25/703367c4-af98-4702-85f0-794b30776a4f.jpg)

在fpm某个版本之前，我们可以将`SCRIPT_FILENAME`的值指定为任意后缀文件，比如`/etc/passwd`；但后来，fpm的默认配置中增加了一个选项`security.limit_extensions`：

```
; Limits the extensions of the main script FPM will allow to parse. This can
; prevent configuration mistakes on the web server side. You should only limit
; FPM to .php extensions to prevent malicious users to use other extensions to
; exectute php code.
; Note: set an empty value to allow all extensions.
; Default Value: .php
;security.limit_extensions = .php .php3 .php4 .php5 .php7
```

其限定了只有某些后缀的文件允许被fpm执行，默认是`.php`。所以，当我们再传入`/etc/passwd`的时候，将会返回`Access denied.`：

[![14931290357686.jpg](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/99d10f40-7dc3-46f3-a0bb-dae71e9d550b.30fa707133a3.jpg)](https://www.leavesongs.com/media/attachment/2017/04/25/99d10f40-7dc3-46f3-a0bb-dae71e9d550b.jpg)

> ps. 这个配置也会影响Nginx解析漏洞，我觉得应该是因为Nginx当时那个解析漏洞，促成PHP-FPM增加了这个安全选项。另外，也有少部分发行版安装中`security.limit_extensions`默认为空，此时就没有任何限制了。

由于这个配置项的限制，如果想利用PHP-FPM的未授权访问漏洞，首先就得找到一个已存在的PHP文件。

万幸的是，通常使用源安装php的时候，服务器上都会附带一些php后缀的文件，我们使用`find / -name "*.php"`来全局搜索一下默认环境：

[![14931297810961.jpg](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/15695b8e-79ae-4f32-b061-cc5f52236e18.a5365d20818a.jpg)](https://www.leavesongs.com/media/attachment/2017/04/25/15695b8e-79ae-4f32-b061-cc5f52236e18.jpg)

找到了不少。这就给我们提供了一条思路，假设我们爆破不出来目标环境的web目录，我们可以找找默认源安装后可能存在的php文件，比如`/usr/local/lib/php/PEAR.php`。

## [任意代码执行](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#_1)

那么，为什么我们控制fastcgi协议通信的内容，就能执行任意PHP代码呢？

理论上当然是不可以的，即使我们能控制`SCRIPT_FILENAME`，让fpm执行任意文件，也只是执行目标服务器上的文件，并不能执行我们需要其执行的文件。

但PHP是一门强大的语言，PHP.INI中有两个有趣的配置项，`auto_prepend_file`和`auto_append_file`。

`auto_prepend_file`是告诉PHP，在执行目标文件之前，先包含`auto_prepend_file`中指定的文件；`auto_append_file`是告诉PHP，在执行完成目标文件后，包含`auto_append_file`指向的文件。

那么就有趣了，假设我们设置`auto_prepend_file`为`php://input`，那么就等于在执行任何php文件前都要包含一遍POST的内容。所以，我们只需要把待执行的代码放在Body中，他们就能被执行了。（当然，还需要开启远程文件包含选项`allow_url_include`）

那么，我们怎么设置`auto_prepend_file`的值？

这又涉及到PHP-FPM的两个环境变量，`PHP_VALUE`和`PHP_ADMIN_VALUE`。这两个环境变量就是用来设置PHP配置项的，`PHP_VALUE`可以设置模式为`PHP_INI_USER`和`PHP_INI_ALL`的选项，`PHP_ADMIN_VALUE`可以设置所有选项。（`disable_functions`除外，这个选项是PHP加载的时候就确定了，在范围内的函数直接不会被加载到PHP上下文中）

所以，我们最后传入如下环境变量：

```
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/index.php',
    'SCRIPT_NAME': '/index.php',
    'QUERY_STRING': '?a=1&b=2',
    'REQUEST_URI': '/index.php?a=1&b=2',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
    'PHP_VALUE': 'auto_prepend_file = php://input',
    'PHP_ADMIN_VALUE': 'allow_url_include = On'
}
```

设置`auto_prepend_file = php://input`且`allow_url_include = On`，然后将我们需要执行的代码放在Body中，即可执行任意代码。

效果如下：

[![14931311523859.jpg](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/e3c3329d-4e0e-4eec-9ea6-4e621cf01f9b.f4321b6236f8.jpg)](https://www.leavesongs.com/media/attachment/2017/04/25/e3c3329d-4e0e-4eec-9ea6-4e621cf01f9b.jpg)

## [EXP编写](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html#exp)

上图中用到的EXP，就是根据之前介绍的fastcgi协议来编写的，代码如下：https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75 。兼容Python2和Python3，方便在内网用。

之前好些人总是拿着一个GO写的工具在用，又不太好用。实际上理解了fastcgi协议，再看看这个源码，就很简单了。

EXP编写我就不讲了，自己读代码吧。


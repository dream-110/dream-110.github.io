## nginx漏洞大全

## nginx解析漏洞

### CVE-2013-4547-nginx文件名逻辑漏洞

**影响版本为**： Nginx 0.8.41 ~ 1.4.3 / 1.5.0 ~ 1.5.7

**漏洞说明：**这个漏洞其实和代码执行没有太大关系，其主要原因是错误地解析了请求的URI，

错误地获取到用户请求的文件名，导致出现权限绕过、代码执行的连带影响。

**漏洞测试**

**环境搭建：**

在本地搭建一个nginx:1.4.2的上传页面

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851035_6040abdb61c2a39a59b2f.png!small)
**漏洞复现过程：**

1.首先判断其文件上传的格式为白名单机制，上传一个1.jpg的木马，抓包后进行修改在其后加入一个空格—>1.jpg

然后放包

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851037_6040abdd21014ed90eaba.png!small)

2.发现其地址
![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851038_6040abde4693952744aef.png!small)

3.构建请求url：http://192.168.127.133:8080/uploadfiles/1.jpgaaaphp

抓包后修改其2进制值将61 61 61 分别改为 20 00 2e

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851038_6040abdeef802bdfe9877.png!small)

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851039_6040abdfba6ed17e6dfce.png!small)

然后放包

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851040_6040abe08da0d6ecc017a.png!small)

### 由于用户配置不当导致解析漏洞

**影响版本：**和nginx,php版本无关，这是由于php中的选项cgi.fix_pathinfo的默认值被开启，所以当nginx看到.php结尾的文件就交给了php处理，相当于iis7.5的解析漏洞

**漏洞复现**：

1.上传一张正常的图片马绕过检测

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851041_6040abe172ee809615745.png!small)

2.然后加/.php这样会发现图片被解析成php代码
![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851043_6040abe3a514dca4fa891.png!small)

### %00截断解析

**影响版本**：0.5，0.6 ，0.7<=0.7.65,0.8<=0.8.37

**漏洞原理**：php-fastcgi在执行php文件时，url在处理%00空字节与fastcgi处理不一致，使得我们在其他文件插入php代码，访问url+%00.php即可执行其中php代码

## CVE-2017-7529 NGINX越界读取缓存漏洞-nginx整数溢出漏洞

**漏洞详情：**

在nginx作为反向代理服务器，且开启了缓存时，攻击者可以构造恶意的range域，来获取相应的服务器中的缓存文件头部信息，导致敏感的服务器信息泄露

相关文章检索：https://www.freebuf.com/articles/terminal/140402.html

**影响版本：**Nginx 0.5.6 - 1.13.2

**环境搭建**

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851047_6040abe762de37963e26d.png!small)

使用脚本 发现其带出部分缓存信息

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851048_6040abe83eeb67d76e4cb.png!small)

## 错误配置

### CRLF注入漏洞

**原理**：CRLF是“回车 + 换行”（\r\n）的简称。在HTTP协议中，HTTP Header与HTTP Body是用两个CRLF分隔的，浏览器就是根据这两个CRLF（使用payload %0a%0d%0a%0d进行测试）来取出HTTP内容并显示出来。所以，一旦我们能够控制HTTP消息头中的字符，注入一些恶意的换行，这样我们就能注入一些会话Cookie（[http://www.xx.com%0a%0d%0a%0dSet-cookie:JSPSESSID%3Dxxx）或者HTML代码（http://www.xx.com/?url=%0a%0d%0a%0d](https://www.freebuf.com/articles/web/265135.html?url=  )<img src=1 onerror=alert("xss")>），所以CRLF Injection又叫HTTP Response Splitting，简称HRS。

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851049_6040abe9ae61a9d8b91fe.png!small)

### 目录穿越漏洞

Nginx在配置别名（Alias）的时候，如果忘记加`/`，将造成一个目录穿越漏洞。

错误的配置文件示例（原本的目的是为了让用户访问到/home/目录下的文件）：

```
location /files {
    alias /home/;
}
```

Payload:`http://your-ip:8081/files../`，成功穿越到根目录：

![img](https://imgurl-1304573507.cos.ap-shanghai.myqcloud.com/1614851050_6040abea997d376c67fbf.png!small)
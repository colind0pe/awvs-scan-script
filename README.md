# awvs-scan-script

## 脚本介绍

调用Acunetix AWVS的API实现批量扫描，并且使用代理池（项目地址[goProxyPool](https://github.com/pingc0y/go_proxy_pool)），实现批量扫描时的每个扫描目标都使用不同的代理IP。

## 脚本功能

* 仅批量添加目标，并设置扫描使用的代理
* 批量添加目标，并使用代理开始扫描
* 获取扫描失败的目标，保存在`log/error_url.txt`中
* 中止所有扫描任务
* 删除扫描器中的所有扫描任务和目标
* 对扫描失败的目标重新进行扫描，先删除扫描器中扫描失败的目标，再将`log/error_url.txt`中的URL添加到重新添加到扫描器中进行扫描。（执行这个操作前请执行【获取扫描失败的目标】）

```
正在扫描: 0 ，等待扫描: 0 ，漏洞数量: {'high': None, 'low': None, 'med': None}
[*] 请选择要进行的操作：
1、批量添加目标，不进行扫描
2、批量添加目标并开始扫描
3、获取扫描失败的目标
4、中止所有扫描任务
5、删除所有目标和扫描任务
6、对扫描失败的目标重新扫描

请输入数字：6
[*] 该操作会先删除扫描器中扫描失败的目标，请先执行【获取扫描失败的目标】
[*] 是否要删除扫描器中扫描失败的目标(y/n)：y

[*] 正在尝试对扫描失败的目标进行重新扫描
[*] 请输入要添加的目标数量(留空则添加txt中全部url)：
```

![](https://raw.githubusercontent.com/colind0pe/awvs-scan-script/master/pic/pic01.png)

## 使用方法

1、启动proxy_pool目录下的代理池程序，程序会开始爬取免费代理并验证代理，大约需要三分钟。代理池程序的详细使用请访问原项目仓库：[goProxyPool](https://github.com/pingc0y/go_proxy_pool)。感谢作者[pingc0y](https://github.com/pingc0y)的贡献。

2、在config.yaml配置文件中替换proxy_pool、awvs_url、api_key为你的代理池、awvs访问地址和API 密钥，同时可以选择修改标签和扫描速度以及扫描的类型。

3、使用python3运行脚本。
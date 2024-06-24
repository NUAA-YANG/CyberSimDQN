"""
@Author：YZX
@Date：2024/6/21 10:44
@Python：3.9
"""

from firewall import Firewall
from node import Node
from vulnerability import Vulnerability
from calculate.vulCal import calculate

"""
================================防火墙====================================
"""
# 防火墙
my_firewall = Firewall(
    fw_name="my_firewall",
    fw_id=1,
    fw_ip="192.168.1.1",
    fw_rule={"source": "192.168.90.1/24", "destination": "192.168.100.1/24",
             "port": "80", "protocol": "TCP", "action": "deny"},
    fw_state="running"
)

"""
================================本地漏洞=====================================
1. 定义为本地攻击
2. 通过横向移动到相邻的节点上
"""
# 永恒之蓝漏洞,它利用了Windows系统的SMB（Server Message Block）服务中的漏洞
# 概括：存在Windows中，攻破后的移动可自定义
EternalBlue = Vulnerability(
    vul_name="EternalBlue",
    vul_id=1,
    vul_cve="CVE-2017-014",
    vul_type="local",
    vul_port=445,
    vul_protocol="TCP",
    vul_os="Windows",
    vul_desc="Exploiting vulnerabilities in SMB services on Windows systems",
    vul_complexity="medium",
    vul_persistence="short",
    vul_interaction="yes",
    vul_authority="user",
    vul_confidentiality="high",
    vul_probability=0.7,
    vul_reward=22,
    vul_cost=18
)

# 漏洞影响Windows打印后台处理程序服务，攻击者可以利用这个漏洞执行远程代码或获得系统权限。
# 概括：存在Windows中，攻破后的移动可自定义
PrintNightmare = Vulnerability(
    vul_name="PrintNightmare",
    vul_id=2,
    vul_cve="CVE-2021-34527",
    vul_type="local",
    vul_port=445,
    vul_protocol="TCP",
    vul_os="Windows",
    vul_desc="Exploiting Windows Print Spooler Service Vulnerability",
    vul_complexity="high",
    vul_persistence="medium",
    vul_interaction="yes",
    vul_authority="root",
    vul_confidentiality="low",
    vul_probability=0.6,
    vul_reward=15,
    vul_cost=25
)

# 该漏洞影响使用Sudo的Linux操作系统，本地攻击者可以通过在系统上执行特制命令从而提权为root
# 概括：存在Linux中，攻破后的移动可自定义
BaronSamedit = Vulnerability(
    vul_name="BaronSamedit",
    vul_id=3,
    vul_cve="CVE-2021-3156",
    vul_type="local",
    vul_port=80,
    vul_protocol="TCP",
    vul_os="Linux",
    vul_desc="Exploiting BaronSamedit vulnerability to elevate permissions",
    vul_complexity="high",
    vul_persistence="long",
    vul_interaction="yes",
    vul_authority="user",
    vul_confidentiality="high",
    vul_probability=0.5,
    vul_reward=24,
    vul_cost=16
)

"""
================================远程漏洞========================================
1. 定义为远程攻击
2. 通过横向移动到相邻和非相邻的节点上
"""
# 产生于：Windows远程桌面服务远程代码执行漏洞
# 影响：攻破后，可访问另一台Windows电脑
# 概括：存在Windows中，攻破后可访问另一个Windows主机
BlueKeep = Vulnerability(
    vul_name="BlueKeep",
    vul_id=4,
    vul_cve="CVE-2019-0708",
    vul_type="remote",
    vul_port=3389,
    vul_protocol="TCP",
    vul_os="Windows",
    vul_desc="Exploiting Remote Desktop Services Vulnerability in Windows System",
    vul_complexity="medium",
    vul_persistence="medium",
    vul_interaction="yes",
    vul_authority="root",
    vul_confidentiality="exHigh",
    vul_probability=0.6,
    vul_reward=23,
    vul_cost=17
)

# 产生于：漏洞存在于Java开发框架Spring的Core模块中
# 影响：攻破后，该漏洞可影响web服务，即可访问存在web服务的电脑
# 概括：存在Spring框架中，攻破后可访问存在Web服务的主机
Spring4Shell = Vulnerability(
    vul_name="Spring4Shell",
    vul_id=5,
    vul_cve="CVE-2022-22965",
    vul_type="remote",
    vul_port=80,
    vul_protocol="HTTP",
    vul_os="Linux",
    vul_desc="Exploiting Java application vulnerabilities in the Spring Framework",
    vul_complexity="low",
    vul_persistence="low",
    vul_interaction="yes",
    vul_authority="user",
    vul_confidentiality="exHigh",
    vul_probability=0.5,
    vul_reward=31,
    vul_cost=9
)

# 产生于：漏洞存在于Oracle WebLogic Server的控制台组件和管理控制台
# 影响：攻破后，该漏洞可控制Oracle数据库服务器
# 概括：存在Oracle中，攻破后可访问存在Oracle Server服务的主机
OracleWebLogicServer = Vulnerability(
    vul_name="OracleWebLogicServer",
    vul_id=6,
    vul_cve="CVE-2020-2574",
    vul_type="remote",
    vul_port=7001,
    vul_protocol="HTTP",
    vul_os="Linux",
    vul_desc="Exploiting this vulnerability to forge digital certificates",
    vul_complexity="low",
    vul_persistence="long",
    vul_interaction="no",
    vul_authority="user",
    vul_confidentiality="low",
    vul_probability=0.6,
    vul_reward=27,
    vul_cost=13
)

# 产生于：漏洞存在于Apache Log4j 2中的JNDI功能（即一种java日志框架）
# 影响：攻破后，该漏洞可访问存在Log4j（日志服务）的应用程序
# 概括：存在Apache Log4j中，攻破后可访问存在Apache Log4j服务的主机
Log4Shell = Vulnerability(
    vul_name="Log4Shell",
    vul_id=7,
    vul_cve="CVE-2021-44228",
    vul_type="remote",
    vul_port=443,
    vul_protocol="HTTPS",
    vul_os="Linux",
    vul_desc="Exploiting service vulnerabilities using Apache Log4j 2 library",
    vul_complexity="low",
    vul_persistence="long",
    vul_interaction="no",
    vul_authority="user",
    vul_confidentiality="medium",
    vul_probability=0.7,
    vul_reward=29,
    vul_cost=11
)

# 产生于：漏洞存在于Java开发框架Apache Struts2的文件上传组件
# 影响：攻破后，攻击者可以利用该漏洞访问和控制web应用程序
# 概括：存在Apache Struts2中，攻破后可访问存在Apache Web服务的主机
Struts2 = Vulnerability(
    vul_name="Struts2",
    vul_id=8,
    vul_cve="CVE-2018-11776",
    vul_type="remote",
    vul_port=443,
    vul_protocol="HTTPS",
    vul_os="Windows",
    vul_desc="Exploiting a Remote Code Vulnerability in the Apache Web Application Framework",
    vul_complexity="low",
    vul_persistence="medium",
    vul_interaction="no",
    vul_authority="user",
    vul_confidentiality="low",
    vul_probability=0.4,
    vul_reward=25,
    vul_cost=15
)

"""
================================节点========================================
1. 每个抽象网络节点存在1-3个漏洞，漏洞为本地漏洞或远程漏洞，可移动到相应节点
2. 每个节点只有一种操作系统，则漏洞适配操作系统应该与节点匹配
3. 利用字典存储所有的节点
"""
# 节点
# 设置本地漏洞和远程漏洞都可以连接到某个节点上
one = Node(
    node_name="one",
    node_id=1,
    node_type="pc",
    node_os="Ubuntu",
    node_ip="192.168.1.1",
    node_services=["ApacheLog4j", "MySQL"],
    node_vul={
        EternalBlue: 2, BlueKeep: 5
    },
    node_value=10
)

two = Node(
    node_name="one",
    node_id=2,
    node_type="pc",
    node_os="Ubuntu",
    node_ip="192.168.1.1",
    node_services=["ApacheLog4j", "MySQL"],
    node_vul={
        EternalBlue: [2], BlueKeep: [5]
    },
    node_value=10
)
# 这里继续描述节点和漏洞情况


# 存放所有节点的字典(需要把所有节点补充进去)
nodeList = {1: one, 2: two}


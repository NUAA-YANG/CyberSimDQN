"""
@Author：YZX
@Date：2024/6/21 10:44
@Python：3.9
"""

from firewall import Firewall
from node import Node
from vulnerability import Vulnerability

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
    vul_probability=0.7
)

# 漏洞影响Windows打印后台处理程序服务，攻击者可以利用这个漏洞执行远程代码或获得系统权限。
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
    vul_probability=0.6
)

# 该漏洞影响使用Sudo的Linux操作系统，本地攻击者可以通过在系统上执行特制命令从而提权为root
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
    vul_probability=0.5
)

"""
================================远程漏洞========================================
1. 定义为远程攻击
2. 通过横向移动到相邻和非相邻的节点上
"""
# Windows远程桌面服务远程代码执行漏洞，它影响了Windows操作系统的远程桌面服务（RDP）
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
    vul_probability=0.6
)

# 该漏洞影响SpringFramework，攻击者可以利用该漏洞执行远程代码
Spring4Shell = Vulnerability(
    vul_name="Spring4Shell",
    vul_id=5,
    vul_cve="CVE-2022-22965",
    vul_type="remote",
    vul_port=80,
    vul_protocol="HTTP",
    vul_os="Linux",
    vul_desc="Exploiting Java application vulnerabilities in the Spring Framework",
    vul_complexity="medium",
    vul_persistence="short",
    vul_interaction="yes",
    vul_authority="user",
    vul_confidentiality="exHigh",
    vul_probability=0.5
)

# Oracle WebLogic Server中的高危漏洞，允许本地攻击者通过利用某些未授权的特性提升权限
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
    vul_persistence="medium",
    vul_interaction="no",
    vul_authority="user",
    vul_confidentiality="low",
    vul_probability=0.6
)

# 攻击者可以通过特制的日志消息执行远程代码
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
    vul_probability=0.7
)

# Apache Web应用框架中的一个远程代码执行漏洞
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
    vul_probability=0.4
)

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
        EternalBlue: [2], BlueKeep: [5]
    },
    node_value=10
)

"""
@Author：YZX
@Date：2024/6/21 10:44
@Python：3.9
"""

from pojo.firewall import Firewall
from pojo.node import Node
from pojo.vulnerability import Vulnerability
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
    vul_protocol="SMB",
    vul_os="Windows",
    vul_desc="Exploiting vulnerabilities in SMB services on Windows systems",
    vul_complexity="medium",
    vul_persistence="short",
    vul_interaction="yes",
    vul_authority="user",
    vul_confidentiality="high",
    vul_probability=0.8,
    vul_reward=25,
    vul_cost=35
)


# 漏洞影响Windows打印后台处理程序服务，攻击者可以利用这个漏洞执行远程代码或获得系统权限。
# 概括：存在Windows中，攻破后的移动可自定义
PrintNightmare = Vulnerability(
    vul_name="PrintNightmare",
    vul_id=2,
    vul_cve="CVE-2021-34527",
    vul_type="local",
    vul_port=135,
    vul_protocol="RPC",
    vul_os="Windows",
    vul_desc="Exploiting Windows Print Spooler Service Vulnerability",
    vul_complexity="high",
    vul_persistence="medium",
    vul_interaction="yes",
    vul_authority="root",
    vul_confidentiality="low",
    vul_probability=0.7,
    vul_reward=10,
    vul_cost=50
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
    vul_probability=0.6,
    vul_reward=29,
    vul_cost=31
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
    vul_protocol="RDP",
    vul_os="Windows",
    vul_desc="Exploiting Remote Desktop Services Vulnerability in Windows System",
    vul_complexity="low",
    vul_persistence="medium",
    vul_interaction="no",
    vul_authority="root",
    vul_confidentiality="exHigh",
    vul_probability=0.7,
    vul_reward=38,
    vul_cost=22
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
    vul_probability=0.7,
    vul_reward=43,
    vul_cost=17
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
    vul_probability=0.5,
    vul_reward=33,
    vul_cost=27
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
    vul_probability=0.9,
    vul_reward=38,
    vul_cost=22
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
    vul_probability=0.6,
    vul_reward=29,
    vul_cost=31
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
    node_os="Linux",
    node_ip="192.168.1.1",
    node_services=["Apache Log4j"],
    node_vul={
        Log4Shell: 10, BaronSamedit: 12
    },
    node_value=10
)

three = Node(
    node_name="three",
    node_id=3,
    node_type="pc",
    node_os="Linux",
    node_ip="192.168.1.3",
    node_services=["Shell"],
    node_vul={
        BaronSamedit: 5
    },
    node_value=10
)

# 这里继续描述节点和漏洞情况
five = Node(
    node_name="five",
    node_id=5,
    node_type="pc",
    node_os="Windows",
    node_ip="192.168.1.5",
    node_services=["Print Spooler", "Apache Struts2", "Apache Web"],
    node_vul={
        PrintNightmare: 3, Struts2: 8
    },
    node_value=10
)

eight = Node(
    node_name="five",
    node_id=8,
    node_type="pc",
    node_os="Linux",
    node_ip="192.168.1.8",
    node_services=["Shell", "Apache Struts2", "Oracle", "Web"],
    node_vul={
        BaronSamedit: 1, OracleWebLogicServer: 5, Spring4Shell: 15
    },
    node_value=10
)

ten = Node(
    node_name="ten",
    node_id=10,
    node_type="pc",
    node_os="Windows",
    node_ip="192.168.1.10",
    node_services=["Oracle"],
    node_vul={
        OracleWebLogicServer: 1
    },
    node_value=10
)

twelve = Node(
    node_name="twelve",
    node_id=12,
    node_type="pc",
    node_os="Windows",
    node_ip="192.168.1.12",
    node_services=["Web", "Apache Log4j", "RDS"],
    node_vul={
        EternalBlue: 1, PrintNightmare: 15
    },
    node_value=10
)

fifteen = Node(
    node_name="fifteen",
    node_id=15,
    node_type="pc",
    node_os="Windows",
    node_ip="192.168.1.15",
    node_services=["Spring", "SMB", "Oracle Server"],
    node_vul={
        EternalBlue: 8, BlueKeep: 12
    },
    node_value=10
)

# 存放所有节点的字典(需要把所有节点补充进去)
nodeList = {1: one, 3: three, 5: five, 8: eight, 10: ten, 12: twelve, 15: fifteen}


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

# 永恒之蓝漏洞,它利用了Windows系统的SMB（Server Message Block）服务中的漏洞
EternalBlue = Vulnerability(
    vul_name="EternalBlue",
    vul_id=1,
    vul_cve="CVE-2017-014",
    vul_type="local",
    vul_voucher=[2],
    vul_to_node_id=[],
    vul_port=445,
    vul_protocol="TCP",
    vul_os="Windows7",
    vul_desc="Exploiting vulnerabilities in SMB services on Windows systems",
    vul_complexity="medium",
    vul_persistence="short",
    vul_interaction="yes",
    vul_authority="user",
    vul_confidentiality="high",
    vul_probability=0.7
)

# Windows远程桌面服务远程代码执行漏洞，它影响了Windows操作系统的远程桌面服务（RDP）
BlueKeep = Vulnerability(
    vul_name="BlueKeep",
    vul_id=2,
    vul_cve="CVE-2019-0708",
    vul_type="remote",
    vul_voucher=[],
    vul_to_node_id=[4],
    vul_port=3389,
    vul_protocol="TCP",
    vul_os="WindowsXP",
    vul_desc="Exploiting Remote Desktop Services Vulnerability in Windows System",
    vul_complexity="medium",
    vul_persistence="medium",
    vul_interaction="yes",
    vul_authority="root",
    vul_confidentiality="exHigh",
    vul_probability=0.6
)

# 节点
one = Node(
    node_name="one",
    node_id=1,
    node_type="pc",
    node_os="ubuntu",
    node_ip="192.168.1.1",
    node_services=["ApacheLog4j", "MySQL"],
    node_vul_id=[EternalBlue, BlueKeep],
    node_value=10
)

"""
EternalBlue = Service(
        "EternalBlue",
        "CVE-2017-014",
        "Windows7",
        "Exploiting vulnerabilities in SMB services on Windows systems",
        "medium", "short", "yes", "user", "high", 0.7)
    # BlueKeep CVE-2019-0708
    # Windows远程桌面服务远程代码执行漏洞，它影响了Windows操作系统的远程桌面服务（RDP）
    BlueKeep = Service(
        "BlueKeep",
        "CVE-2019-0708",
        "WindowsXP",
        "Exploiting Remote Desktop Services Vulnerability in Windows System",
        "medium", "medium", "yes", "root", "exHigh", 0.6)
    # Spring4Shell CVE-2022-22965
    # 该漏洞影响SpringFramework，攻击者可以利用该漏洞执行远程代码
    Spring4Shell = Service(
        "Spring4Shell",
        "CVE-2022-22965",
        "Ubuntu",
        "Exploiting Java application vulnerabilities in the Spring Framework",
        "medium", "short", "yes", "user", "exHigh", 0.5)
    # MySQLServer CVE-2020-2574
    # MySQL Server 中的存储过程中存在一个漏洞，允许本地攻击者通过利用某些未授权的特性提升权限
    MySQLServer = Service(
        "MySQLServer",
        "CVE-2020-0601",
        "Windows10",
        "Exploiting this vulnerability to forge digital certificates",
        "low", "medium", "no", "user", "low", 0.6)
    # Log4J CVE-2021-44228
    # 攻击者可以通过特制的日志消息执行远程代码
    Log4J = Service(
        "Log4J",
        "CVE-2021-44228",
        "Ubuntu",
        "Exploiting service vulnerabilities using Apache Log4j 2 library",
        "low", "long", "no", "user", "medium", 0.7)
    # Struts2 CVE-2018-11776
    # Apache Web应用框架中的一个远程代码执行漏洞
    Struts2 = Service(
        "Struts2",
        "CVE-2018-11776",
        "Ubuntu",
        "Exploiting a Remote Code Vulnerability in the Apache Web Application Framework",
        "low", "medium", "no", "user", "low", 0.4)
    # PrintNightmare CVE-2021-34527
    # 漏洞影响Windows打印后台处理程序服务，攻击者可以利用这个漏洞执行远程代码或获得系统权限。
    PrintNightmare = Service(
        "PrintNightmare",
        "CVE-2021-34527",
        "Windows10",
        "Exploiting Windows Print Spooler Service Vulnerability",
        "high", "medium", "yes", "root", "low", 0.6)
    # SMBGhost CVE-2020-0796
    # 漏洞存在于SMBv3协议中，允许攻击者在未授权的情况下远程执行代码
    SMBGhost = Service(
        "SMBGhost",
        "CVE-2020-0796",
        "Windows10",
        "Exploiting SMBv3 protocol vulnerabilities",
        "high", "long", "yes", "user", "high", 0.5)

"""
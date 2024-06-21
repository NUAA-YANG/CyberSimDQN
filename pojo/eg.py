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
    fw_state="running")

# 节点
one = Node(
    node_name="one",
    node_id=1,
    node_type="pc",
    node_os="ubuntu",
    node_ip="192.168.1.1",
    node_services=["ApacheLog4j", "MySQL"],
    node_vul_id=[2, 6],
    node_value=10
)

# 永恒之蓝漏洞,它利用了Windows系统的SMB（Server Message Block）服务中的漏洞
EternalBlue = Vulnerability(
    vul_name="EternalBlue",
    vul_id=1,
    vul_cve="CVE-2017-014",
    vul_type="local",
    vul_voucher=[2, 5],
    vul_to_node_id=[],
    vul_port=80,
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

"""
@Author：YZX
@Date：2024/6/21 10:33
@Python：3.9
"""


# 防火墙节点类
class Firewall:
    def __init__(self, fw_name, fw_id, fw_ip, fw_rule, fw_state):
        # 防火墙名称
        self.fw_name = fw_name
        # 防火墙编号
        self.fw_id = fw_id
        # 防火墙ip地址
        self.fw_ip = fw_ip
        # 防火墙规则集：{"source": "192.168.90.1/24", "destination": "192.168.100.1/24", "port": "80", "protocol": "TCP", "action": "deny"}
        self.fw_rule = fw_rule
        # 防火墙运行状态：[running stop]
        self.fw_state = fw_state

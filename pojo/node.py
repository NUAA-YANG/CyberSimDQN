"""
@Author：YZX
@Date：2024/6/21 9:46
@Python：3.9
"""


# 节点类
class Node:
    def __init__(self, node_name, node_id, node_type, node_os,
                 node_ip, node_services, node_vul_id, node_value):
        # 节点名称
        self.node_name = node_name
        # 节点编号
        self.node_id = node_id
        # 节点类型
        self.node_type = node_type
        # 节点操作系统：[ubuntu windows]
        self.node_os = node_os
        # 节点ip地址
        self.node_ip = node_ip
        # 节点运行的服务：["ApacheLog4j"、MySQL"]
        self.node_services = node_services
        # 节点拥有漏洞编号
        self.node_vul_id = node_vul_id
        # 节点的价值
        self.node_value = node_value

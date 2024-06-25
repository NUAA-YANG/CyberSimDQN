"""
@Author：YZX
@Date：2024/6/25 10:57
@Python：3.9
"""


# 链路类
class Link:
    def __init__(self, link_name, link_id, link_protocol, link_from_node, link_to_node):
        # 链路名称
        self.link_name = link_name
        # 链路id
        self.link_id = link_id
        # 链路协议
        self.link_protocol = link_protocol
        # 链路连接头节点
        self.link_from_node = link_from_node
        # 链路连接尾节点
        self.link_to_node = link_to_node

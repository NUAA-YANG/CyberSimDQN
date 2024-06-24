"""
@Author：YZX
@Date：2024/6/21 14:54
@Python：3.9
"""
import numpy as np


# 根据CVSS生成节点的消耗
def calculate(vulnerability):
    # 攻击者倾向于服务复杂程度低的服务
    complexityMap = {"low": 1, "medium": 3, "high": 5}
    # 攻击者倾向于漏洞被开辟后的持续时间长的服务
    persistenceMap = {"long": 1, "medium": 3, "short": 5}
    # 攻击者倾向于不需要交互的服务
    interactionMap = {"no": 2, "yes": 5}
    # 攻击者倾向于用户权限就可以放访问服务
    authorityMap = {"user": 2, "root": 5}
    # 攻击者倾向于机密性高的服务
    confidentialityMap = {"exHigh": 1, "high": 3, "medium": 5, "low": 7}
    # 记录每次攻击的消耗
    vulnerability.vul_cost = round(
        complexityMap.get(vulnerability.vul_complexity, 0) + persistenceMap.get(vulnerability.vul_persistence, 0) +
        interactionMap.get(vulnerability.vul_interaction, 0) + authorityMap.get(vulnerability.vul_authority, 0) +
        confidentialityMap.get(vulnerability.vul_confidentiality, 0), 3)
    vulnerability.vul_reward = 40-vulnerability.vul_cost
    # 返回漏洞
    return vulnerability


# 记录网络的连接情况
def connected():
    # 链路连接
    coon = ["0_1", "0_2", "0_3", "0_14", "1_7", "1_8", "1_16", "2_5", "3_4",
            "3_8", "4_6", "4_10", "5_10", "5_12", "6_7", "7_8", "7_9", "8_11",
            "9_10", "9_11", "9_13", "10_12", "11_12", "13_15"]
    coonArray = np.zeros((17, 17))
    for link in coon:
        node = str.split(link, "_")
        # 两个节点
        x = int(node[0])
        y = int(node[1])
        coonArray[x][y] = 1
        coonArray[y][x] = 1
    # 1表示连接，0表示不连接
    return coonArray

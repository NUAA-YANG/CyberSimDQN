"""
@Author：YZX
@Date：2024/6/21 14:54
@Python：3.9
"""
import numpy as np


# 根据CVSS生成节点的消耗
def calculate(vulnerability):
    # 攻击者倾向于服务复杂程度低的服务
    complexityMap = {"low": 1, "medium": 5, "high": 25}
    # 攻击者倾向于漏洞被开辟后的持续时间长的服务
    persistenceMap = {"long": 1, "medium": 5, "short": 25}
    # 攻击者倾向于不需要交互的服务
    interactionMap = {"no": 1, "yes": 10}
    # 攻击者倾向于用户权限就可以放访问服务
    authorityMap = {"user": 1, "root": 15}
    # 攻击者倾向于机密性高的服务
    confidentialityMap = {"exHigh": 0, "high": 5, "medium": 15, "low": 30}
    # 记录每次攻击的消耗
    vulnerability.vul_cost = round(
        complexityMap.get(vulnerability.vul_complexity, 0) + persistenceMap.get(vulnerability.vul_persistence, 0) +
        interactionMap.get(vulnerability.vul_interaction, 0) + authorityMap.get(vulnerability.vul_authority, 0) +
        confidentialityMap.get(vulnerability.vul_confidentiality, 0), 3)
    vulnerability.vul_reward = 90-vulnerability.vul_cost
    # 返回漏洞
    return vulnerability

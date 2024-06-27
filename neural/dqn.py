"""
@Author：YZX
@Date：2024/6/21 15:07
@Python：3.9
"""
import random

import numpy as np
import torch
from matplotlib import pyplot as plt, rcParams
from torch import nn
import networkx as nx
from neural.net import Net


# 构建DQN网络
class DQN:
    # 状态空间大小、动作空间大小、利用GPU加速、经验池大小、学习率、奖励程度
    # 贪婪选择概率、最大贪婪选择概率、贪婪概率的增加率
    # 更新目标网络步数、随机抽取经验数量、连接矩阵
    def __init__(self, statesLen, actionsLen, device, memorySize, learningRate, gamma, greedy, maxGreedy,
                 increaseRate, reloadStep, batchSize, nodeList):
        # 状态空间大小
        self.statesLen = statesLen
        # 动作空间大小
        self.actionsLen = actionsLen
        # 利用gpu加速
        self.device = device
        # 经验池大小
        self.memorySize = memorySize
        # 学习率
        self.learningRate = learningRate
        # 奖励程度
        self.gamma = gamma
        # 贪婪选择概率
        self.greedy = greedy
        # 最大贪婪选择概率
        self.maxGreedy = maxGreedy
        # 贪婪概率的增加率
        self.increaseRate = increaseRate
        # 每走多少步，更新一次target网络
        self.reloadStep = reloadStep
        # 从样本数据经验池中随机获得多少组经验
        self.batchSize = batchSize
        # 环境
        self.nodeList = nodeList

        # 创建一个eval网络，计算当前状态下的 Q 值，估计当前策略的质量
        self.evalNet = Net(self.statesLen, self.actionsLen).to(self.device)
        # 创建一个target网络，计算目标 Q 值，提供一个相对稳定的目标值
        self.targetNet = Net(self.statesLen, self.actionsLen).to(self.device)

        # 损失函数
        self.loss = nn.MSELoss()
        # 优化器
        self.optimizer = torch.optim.Adam(self.evalNet.parameters(), lr=self.learningRate)
        # 记录当前是第几个记忆，若大小超过memorySize则重新覆盖
        self.memoryCount = 0
        # 创建记忆矩阵：当前节点名称+攻击节点名称+奖励+下一个状态
        # 为什么这里都是self.statesLen表示，因为动作即选择下一个节点，是状态表示，下个状态也状态表示的
        # 例如 np.zeros((2000, 4))表示创建一个2000行4列的二维矩阵
        self.memory = np.zeros((self.memorySize, self.statesLen + self.statesLen + 1 + self.statesLen))
        # 记录学习总步数，每选择一个动作就加 1，用作整除reloadStep，更新target网络
        self.learnStepCount = 0
        # 记录损失值
        self.cost = []

    # 传入一个集合，随机选择一个节点作为初试状态
    @staticmethod
    def reset(nodeList):
        keys = list(nodeList.keys())
        return random.choice(keys)

    # 构建掩码
    def generateMask(self, state, passNode):
        # 获取当前节点信息
        node = self.nodeList[state]
        # 获取当前节点的漏洞信息
        node_vul = node.node_vul
        # 生成掩码
        # 如果节点包含2个漏洞，动作大小为3，则生成掩码为[1,1,0]，即表示存在两个漏洞
        mask = []
        for i in range(self.actionsLen):
            if i < len(node_vul):
                mask.append(1)
            else:
                mask.append(0)
        # 排除已经选择过的节点
        # 例如第二个漏洞已经被利用过，则掩码由[1,1,0]变为[1,0,0]
        count = 0
        for value in node_vul.values():
            if value in passNode:
                mask[count] = 0
            count += 1
        return mask

    # 根据漏洞的序号获取漏洞的名称
    def getVulByIndex(self, state, index):
        # 获取当前节点信息
        node = self.nodeList[state]
        # 获取当前节点的漏洞信息
        node_vul = node.node_vul
        # 将键转换为列表
        node_vul_list = list(node_vul.keys())
        # 获取索引位置index的漏洞名称
        return node_vul_list[index]

    """
    动作选择，传入的参数为当前节点信息：
    """

    def chooseAction(self, state, mask):
        # 动态变化贪婪选择概率，保证其逐渐增加
        self.greedy = min(self.maxGreedy, (self.greedy + self.increaseRate))
        # 选择较大的值
        if np.random.uniform() < self.greedy:
            # 扩展一行,因为网络是多维矩阵,输入是至少两维，例如 state 为[2]，那么操作之后变成了[[2]]，同时将张量移动到GPU上
            stateTensor = torch.unsqueeze(torch.FloatTensor([state]), 0).to(self.device)
            # 通过神经网络获取动作对应的值的集合（但是存在无效掩码的动作）
            actionValueList = self.evalNet.forward(stateTensor).detach().cpu().numpy().squeeze()
            # 将掩码为0的地方设置为-np.inf，而为1的地方直接设置为actionValueList的值
            maskedActionValueList = np.where(mask, actionValueList, -np.inf)
            action = np.argmax(maskedActionValueList)
        else:
            # 掩码全部为0（代表该节点已经没有漏洞可用），随机选择一个漏洞
            if set(mask) == {0}:
                # 获取漏洞信息
                node_vul = self.nodeList[state].node_vul
                # 从所有漏洞中随机选择一个漏洞对应的索引
                action = random.randrange(0, len(node_vul))
            else:
                # 掩码不是全部为0，则判定在第几个索引位置有值（即存在几个有效漏洞），例如mask=[1,1,0]，validActions=[0,1]
                validActions = [i for i, valid in enumerate(mask) if valid]
                # 从validActions中随机选择一个值
                action = random.choice(validActions)
        return action

    # 根据动作推测下一个状态
    # 这里的状态是节点，动作是选择某个漏洞的名字
    def getRewardAndNextState(self, state, action):
        # 获取当前节点信息
        node = self.nodeList[state]
        # 获取当前节点的所有漏洞信息
        node_vul = node.node_vul
        # 从当前节点状态下，动作对应的漏洞
        vul = action
        # 获取漏洞对应的转移节点
        nextState = node_vul[vul]
        # =========================获取固定奖励======================
        reward = vul.vul_reward

        # =========================动态渗透获取奖励======================
        # # 对漏洞进行渗透，初始渗透次数为1
        # count = 1
        # # 随机数比渗透成功概率大，说明失败，需要再次渗透，次数+1
        # while np.random.uniform() > vul.vul_probability:
        #     count += 1
        # # 到这里说明渗透成功，返回渗透奖励
        # reward = vul.vul_reward - count * vul.vul_cost

        return reward, nextState

    # 存储学习经验，包括当前节点的名称，攻击节点的名称，奖励，下一个状态
    def storeMemory(self, state, action, reward, nextState):
        # 为保证数据类型一致，全部转化为集合，以np类型捆绑经验存储
        transition = np.hstack((state, action, reward, nextState))
        # index 是一次录入的数据在 memorySize 的哪一个位置
        # 例如 memorySize=2000，当memoryCount<=2000时候，则直接存放；若memoryCount>2000，则取余后覆盖存放
        index = self.memoryCount % self.memorySize
        # 如果记忆超过上线，我们重新索引，即覆盖老的记忆
        # [index, :]表示选择 memory 数组的第 index 行全部数据，例如 memory[15, :]表示15行的所有数据
        self.memory[index, :] = transition
        # 经验池加1
        self.memoryCount += 1

    # 训练：evalNet是每次learn就进行更新，targetNet是达到次数后更新
    def learn(self):
        # 更新targetNet，每循环多少次就更新一下
        if self.learnStepCount % self.reloadStep == 0:
            self.targetNet.load_state_dict((self.evalNet.state_dict()))
        # 每次学习都要增加一次学习步数
        self.learnStepCount += 1
        # 经验池已满，从memorySize中随机选取batchSize个整数
        # 例如 np.random.choice(2000, 16)是从整数范围 [0, 2000) 中随机选择了 16 个整数。
        if self.memoryCount > self.memorySize:
            sampleIndex = np.random.choice(self.memorySize, self.batchSize)
        else:
            # 经验池未满，从现有的经验memoryCount中随机抽取
            sampleIndex = np.random.choice(self.memoryCount, self.batchSize)
        # 按照随机获得的索引值获取对应的行的记忆数据，此时memory是一个二维数组
        memory = self.memory[sampleIndex, :]
        # 从记忆当中获取【状态】列
        state = torch.FloatTensor(memory[:, :1]).to(self.device)
        # 从记忆当中获取【动作】列
        action = torch.FloatTensor(memory[:, 1:2]).to(self.device)
        # 从记忆当中获取【奖励】列
        reward = torch.FloatTensor(memory[:, 2:3]).to(self.device)
        # 从记忆当中获取【下一状态】列
        nextState = torch.FloatTensor(memory[:, 3:4]).to(self.device)

        # qEval 当前状态下执行动作的预测 value，即获取了所有状态-动作对应的值
        qEval = self.evalNet.forward(state).gather(1, action.to(torch.long))
        # 根据下一步的状态，获取其中Q值最大的
        qNext = self.targetNet.forward(nextState).detach()
        # qTarget 当前状态下执行动作的实际value
        qTarget = reward + self.gamma * qNext.max(1)[0].unsqueeze(1)
        # 计算损失值
        loss = self.loss(qEval, qTarget)
        # 梯度重置
        self.optimizer.zero_grad()
        # 反向求导
        loss.backward()
        # 记录损失值
        self.cost.append(loss.detach().cpu().numpy())
        # 更新模型参数
        self.optimizer.step()

    # 绘制损失图
    @staticmethod
    def drawImage(title, xValue, yValue, xLabel, yLabel):
        plt.plot(np.arange(xValue), yValue)
        plt.xlabel(xLabel)
        plt.ylabel(yLabel)
        plt.title(title)
        plt.show()


    # 绘制路径图片
    @staticmethod
    def drawRouteImage(drawNode, drawVul):

        rcParams['font.sans-serif'] = ['SimHei']  # 使用SimHei字体来支持中文
        rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

        # 创建一个有向图
        G = nx.DiGraph()

        # 添加节点和边，边上标注漏洞名称
        edges = [
            (5, 3, ''),
            (5, 8, ''),
            (8, 1, ''),
            (8, 15, ''),
            (1, 10, ''),
            (1, 12, ''),
            (12, 15, ''),
            (15, 9, '')
        ]
        G.add_weighted_edges_from(edges)

        # 设置节点的位置
        positions = {
            1: (0.5, 1),
            3: (0, 0.6),
            5: (0, 0.3),
            8: (0, 0),
            9: (1, 0.7),
            15: (1.5, 0.5),
            10: (0.5, 0),
            12: (1, 0)
        }

        # 创建一个绘图
        plt.figure(figsize=(10, 8))

        # 绘制节点，用较大的实心点表示
        nx.draw_networkx_nodes(G, pos=positions, node_size=800, node_color='lightgrey', edgecolors='black',
                               linewidths=1)

        # 绘制边，使用箭头表示
        nx.draw_networkx_edges(G, pos=positions, arrowstyle='-', arrowsize=20, edge_color='black')

        # 在边上添加漏洞名称
        for (u, v, d) in G.edges(data=True):
            x_start, y_start = positions[u]
            x_end, y_end = positions[v]
            x_mid = (x_start + x_end) / 2
            y_mid = (y_start + y_end) / 2
            plt.text(x_mid, y_mid, d['weight'], fontsize=12, color='red', ha='center', va='center')

        # 添加节点标签
        nx.draw_networkx_labels(G, pos=positions, labels={n: n for n in G.nodes()}, font_size=12, font_color='red')

        highlight_path = drawNode
        nx.draw_networkx_edges(G, pos=positions, edgelist=highlight_path, edge_color='blue', width=3, arrowstyle='->',
                               arrowsize=25)

        # 绘制特定的注释
        path_texts = drawVul

        for (u, v), text in path_texts.items():
            x_start, y_start = positions[u]
            x_end, y_end = positions[v]
            x_mid = (x_start + x_end) / 2
            y_mid = (y_start + y_end) / 2
            plt.text(x_mid, y_mid, text, fontsize=12, color='blue', ha='center', va='center',
                     bbox=dict(facecolor='white', edgecolor='none', alpha=0.7))

        # 隐藏坐标轴
        plt.axis('off')

        # 显示图形
        plt.show()

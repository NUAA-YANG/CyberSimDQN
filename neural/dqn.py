"""
@Author：YZX
@Date：2024/6/21 15:07
@Python：3.9
"""
import numpy as np
import torch
from matplotlib import pyplot as plt
from torch import nn

from neural.net import Net


# 构建DQN网络
class DQN:
    # 状态空间大小、动作空间大小、利用GPU加速、经验池大小、学习率、奖励程度
    # 贪婪选择概率、最大贪婪选择概率、贪婪概率的增加率
    # 更新目标网络步数、随机抽取经验数量、连接矩阵
    def __init__(self, statesLen, actionsLen, device, memorySize, learningRate, gamma, eGreedy, maxEGreedy,
                 increaseRate, reloadStep, batchSize, coonArray, nodeVulList, staticReward, dynamicReward):
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
        self.eGreedy = eGreedy
        # 最大贪婪选择概率
        self.maxEGreedy = maxEGreedy
        # 贪婪概率的增加率
        self.increaseRate = increaseRate
        # 每走多少步，更新一次target网络
        self.reloadStep = reloadStep
        # 从样本数据经验池中随机获得多少组经验
        self.batchSize = batchSize
        # 连接矩阵
        self.coonArray = coonArray

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

    # 动作选择，传入的参数为状态以及当前节点的漏洞
    def chooseAction(self, state):
        # 动态变化贪婪选择概率，保证其逐渐增加
        self.eGreedy = min(self.maxEGreedy, (self.eGreedy + self.increaseRate))
        # 选择较大的值
        if np.random.uniform() < self.eGreedy:
            # 扩展一行,因为网络是多维矩阵,输入是至少两维，例如 state 为[2]，那么操作之后变成了[[2]]，同时将张量移动到GPU上
            stateTensor = torch.unsqueeze(torch.FloatTensor([state]), 0).to(self.device)
            # 通过神经网络获取动作对应的值的集合
            actionValueList = self.evalNet.forward(stateTensor)
            # 获取最大的索引
            action = torch.max(actionValueList, 1)[1].data.numpy()[0]
        else:
            action = np.random.randint(0, self.actionsLen)
        return action

    # 根据状态和动作推测下一个状态
    @staticmethod
    def getRewardAndNextState(state, action):
        # 动态奖励值中获取值
        reward = 0
        nextState = action
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
        state = torch.FloatTensor(memory[:, :self.statesLen]).to(self.device)
        # 从记忆当中获取【动作】列
        action = torch.FloatTensor(memory[:, self.statesLen:self.statesLen * 2]).to(self.device)
        # 从记忆当中获取【奖励】列
        reward = torch.FloatTensor(memory[:, self.statesLen * 2:self.statesLen * 2 + 1]).to(self.device)
        # 从记忆当中获取【下一状态】列
        nextState = torch.FloatTensor(memory[:, self.statesLen * 2 + 1:self.statesLen * 3 + 1]).to(self.device)

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

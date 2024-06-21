"""
@Author：YZX
@Date：2024/6/21 15:12
@Python：3.9
"""
from torch import nn


# 用于构建深度神经网络
# states表示输入的状态，actions表示动作的集合
class Net(nn.Module):
    # 表示状态的个数和动作的个数
    def __init__(self, statesLen, actionsLen):
        super(Net, self).__init__()
        # 创建一个从输入层到第一个隐藏层的全连接层
        self.input = nn.Linear(statesLen, statesLen * 16)
        # 创建第一个隐藏层
        self.f1 = nn.Linear(statesLen * 16, statesLen * 64)
        # 创建第二个隐藏层
        self.f2 = nn.Linear(statesLen * 64, statesLen * 128)
        # 创建第三个隐藏层
        self.f3 = nn.Linear(statesLen * 128, statesLen * 64)
        # 创建第四个隐藏层
        self.f4 = nn.Linear(statesLen * 64, statesLen * 16)
        # 创建最后一个隐藏层到输出层的全连接层
        self.output = nn.Linear(statesLen * 16, actionsLen)
        # 激活函数
        self.relu = nn.ReLU()

    # 预测动作的值
    def forward(self, state):
        # 第一步：全连接层线性激活
        state = self.relu(self.input(state))
        # 第二步：隐藏层线性激活
        state = self.relu(self.f1(state))
        state = self.relu(self.f2(state))
        state = self.relu(self.f3(state))
        state = self.relu(self.f4(state))
        # 第三步：全连接输出
        out = self.output(state)
        return out

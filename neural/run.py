"""
@Author：YZX
@Date：2024/6/21 16:04
@Python：3.9
"""
import torch
from neural.dqn import DQN
from pojo import env

# 主迭代函数，终止条件是达到迭代次数
# GPU加速
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
# 经验池
memorySize = 2000
# 学习率
learningRate = 0.001
# 奖励程度
gamma = 0.9
# 起始贪婪选择概率
greedy = 0
# 最大贪婪选择概率
maxGreedy = 1
# 贪婪概率的增加率
increaseRate = 0.0002
# 每走多少步，更新一次target网络
reloadStep = 100
# 从样本数据经验池中随机获得多少组经验
batchSize = 32
# 迭代次数
trainingEpisodeCount = 1300
# 每次迭代的最大步数
episodeStepCount = 30
# 起始节点
src = 5
# 环境
nodeList = env.nodeList

# 状态，暂定为节点的名称
stateInfo = ["node_id"]
# 动作，设置最大的动作数量为3，当动作不满足3时，填充无效动作
attackAction = ["vul_1", "vul_2", "vul_3"]
# 总共已经走了多少步，用来调用网络进行学习
step = 0
# 记录每次获得的奖励
rewardList = []
# 画图节点
drawNode = []
# 画图漏洞
drawVul = {}

# 智能体
agent = DQN(statesLen=len(stateInfo), actionsLen=len(attackAction), device=device, memorySize=memorySize,
            learningRate=learningRate, gamma=gamma, greedy=greedy, maxGreedy=maxGreedy,
            increaseRate=increaseRate, reloadStep=reloadStep, batchSize=batchSize, nodeList=nodeList)
print("**********************开始渗透**********************")
for episode in range(trainingEpisodeCount):
    # 起始节点
    state = src
    # 每次迭代的奖励值
    episodeReward = 0
    # 每轮走的步数
    episodeStep = 0
    # 记录走过的节点
    passNode = [state]
    # 记录攻击方式
    attackList = []
    while True:
        # 根据当前节点拥有的漏洞数量，生成动作掩码
        mask = agent.generateMask(state, passNode)
        # 选择动作（这里获取的是漏洞的序号）
        action = agent.chooseAction(state, mask)
        # 将漏洞序号转化为对应渗透的漏洞名称
        vul = agent.getVulByIndex(state, action)
        # 计算奖励和下一状态，注意，这里传入的已经是漏洞的名称
        reward, nextState = agent.getRewardAndNextState(state, vul)
        # 再次判断是否存在重复节点，若存在则给予一个很大的负值奖励
        if nextState in passNode:
            reward = -500
        # 存储记忆
        agent.storeMemory(state, action, reward, nextState)
        # 随机抽取学习
        if step > 750:
            # 学习训练
            agent.learn()
        # 达到最大迭代步数 or  掩码全部为0（代表该节点已经没有漏洞可用） or 出现重复的节点
        if episodeStep > episodeStepCount or set(mask) == {0} or nextState in passNode:
            break
        # 记录当前选择的节点
        passNode.append(nextState)
        # 记录渗透的漏洞名称
        attackList.append(vul.vul_name)
        # 添加画图数据
        if episode == trainingEpisodeCount - 1:
            # 添加画图节点
            drawNode.append([state, nextState])
            # 添加画图漏洞
            drawVul[(state, nextState)] = vul.vul_name
        # 更新步数
        step += 1
        episodeStep += 1
        # 记录每次选择动作奖励
        episodeReward += reward
        # 更新状态
        state = nextState
    # 记录每次循环的奖励值大小
    rewardList.append(episodeReward)
    print("当前迭代次数：", episode, "，当前奖励为：", episodeReward, "，当前概率为：", agent.greedy, ", 移动节点顺序：",
          passNode, "，攻击漏洞顺序：", attackList)

# 绘制奖励图
agent.drawImage("Cost-The src node is 5", len(agent.cost), agent.cost, "learnStep", "cost")
agent.drawImage("Reward-The src node is 5", trainingEpisodeCount, rewardList, "episode", "reward")
agent.drawRouteImage(drawNode, drawVul)

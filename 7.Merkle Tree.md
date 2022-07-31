# 实验项目
Impl Merkle Tree following RFC6962 
# 实验完成人
姓名：时梦雅

学号：202000460054
# 运行指导
可以直接运行
# 实验思路
给定一系列数据块 data blocks，对 data blocks 分别用 sha256算法计算哈希值每条数据进行 hash，从第 0 条数据开始，对每两个交易的哈希(hash)相加结果进行哈希(hash)，然后多次迭代直到最后只有一个哈希值，该哈希值就是默克尔根(Merkle root)，整个树状结构数据就是默克尔树。根据 RFC 6962 标准，如果是奇数个结点，就将最后一个结点不断上移到树的上一层，直到加上该结点，树的该层结点数为偶数，这时就可以两两进行合并。Merkle Tree 可以用来检验数据的完整性和正确性，即一个 data block 的改动或缺失，就会导致 Merkle root 的改变。
# 代码实现
首先定义了一个 Iint（node_num）初始化函数，node_num 是数据结点的数量。该函数的功能是将后续需要的数据进行初始化，例如：计算树的深度，生成存储树各层结点的列表 tree 等。同时，该函数还负责将数据结点利用 sha256 算法进行 hash，根据 RFC 6962 标准，hash 之前需要填充“0x00”。生成 Merkle Tree 的函数为 create_tree，利用递归思想，先判断输入的结点列表是不是只有一个结点，如果只有一个结点，该结点就是 root 结点，直接返回该结点。如果不是，就将结点两两合并，填充“0x01”后，利用 sha256 算法进行 hash，将这一系列 hash 作为新的结点列表。如果是奇数个结点，就将最后一个结点直接加入到新的结点列表中。将新的结点列表存储在对应的 tree 项中，然后利用递归思想，返回 create_tree(new_node_list,k)。如此递归下去，直到结点列表只剩一个结点，那么该结点就是根结点，直接返回便可。
# 实验代码
    import hashlib
    import random
    import math
    def Init(node_num):                     #将各项数据进行初始化
        if node_num & (node_num - 1) == 0:  # n为2的幂次
            deep = int(math.log(node_num, 2)) + 1
        else:                               # n不为2的幂次
            deep = int(math.log(node_num, 2)) + 2
        k = deep
        tree = [None] * k
        leaf_node = [None] * node_num
        data_block = [None] * node_num
        t = 'smyyaobaofu'
        tree[k - 1] = data_block
        k = k - 2
        for i in range(node_num):  # 生成叶子结点
            for j in range(10):
                t += random.choice('qwertyuiopasdfghjklzxcvbnm')
            leaf_node[i] = t
            data_block[i] = hash_sha256('00' + t)
        return k,deep,tree,leaf_node,data_block
    def hash_sha256(data):              #hash函数
        obj = hashlib.sha256()
        obj.update(data.encode('utf-8'))
        return obj.hexdigest()
    # def create_tree(node_list,k):        #创建Merkle Tree
    def create_tree(node_list):
        l = len(node_list)
        if l == 1:
            return node_list[0]         #如果只有一个结点，直接返回
        new_node_list = []
        for i in range(0, l-1, 2):      #无论结点数是偶数还是奇数，把相邻的两个合并，偶数的话所有结点正好全部合并，奇数的话还剩最后一个结点
            new_node_list.append(hash_sha256('01' + node_list[i] + node_list[i+1]))
            if l % 2 == 1:
            new_node_list.append(node_list[l-1])
        # if len(new_node_list) % 2 == 0 or k == 0:
        #     tree[k] = new_node_list
         # else:
        #     tree[k] = new_node_list[0:len(new_node_list)-1]
        # k = k-1
        # return create_tree(new_node_list,k)
        return create_tree(new_node_list)

    k,deep,tree,leaf_node,data_block = Init(1000)   # 改成10w即符合题意，但是时间开销大
    
    root = create_tree(data_block)
    # print('根结点的值为:', create_tree(data_block, k))
    # for m in range(deep):
    #     print('树的第', m, '层节点:', tree[m])

    #存在性证明：
    hash_index = []
    direction  = []

    #利用 path 函数，生成给定结点的审计路径，如果结点数为 1，那么直接返回该结点的 hash 值即可。如果结点数大于 1，就按照审计路径的定义，生成审计路径，并不断将路径中的 hash 值存到hash_index 列表中。
    def path(m,node_num): 
        global hash_index
        global data_block
        if node_num == 1:
            hash_index.append(data_block[0])
            return 0
        if node_num & (node_num - 1) == 0:
            p = 2 ** (int(math.log(node_num, 2))-1)
        else:
            p = 2 ** int(math.log(node_num, 2))
        if m < p:
            hash_index.append(create_tree(data_block[p:node_num]))
            data_block = data_block[0:p]
            new_m = m
            new_node_num = p
            direction.append(1)
        else:
            hash_index.append(create_tree(data_block[0:p]))
            data_block = data_block[p:node_num]
            new_m = m - p
            new_node_num = node_num - p
            direction.append(2)
        return path(new_m,new_node_num)
    
    #Calculate_hash 函数，每次取 hash_index 列表中最后两个 hash 值进行合并，形成新的 hash 值。
    def Calculate_hash():
        l = len(hash_index)
        if l == 1:
            return hash_index[0]
        if direction[l-2] == 1:
            hash_index[l-2] = hash_sha256('01' + hash_index[l-1] + hash_index[l-2])
        else:
            hash_index[l-2] = hash_sha256('01' + hash_index[l - 2] + hash_index[l - 1])
        hash_index.pop()
        direction.pop()
        return Calculate_hash()
    
    def existence(m,node_num):
        path(m, node_num)
        print('给定数据为：',leaf_node[m])
        a = Calculate_hash()
        if root == a:
            print('该叶子结点存在')
            return
        else:
            print('该叶子结点不存在')
            return
    existence(4,1000)

# 实验截图
![merkle树](https://user-images.githubusercontent.com/109722365/181865428-56484304-cac8-4c2c-a10e-3528fac8dc40.png)

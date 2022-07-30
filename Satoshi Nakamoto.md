# 此代码为项目：证明我是中本聪
# 实验思路
基于数字签名。
中本聪创世区块挖矿地址1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa；转成ASCII码十六进制为3141317a5031655035514765666932444d505466544c35534c6d7637446976664e61；二进制为110001010000010011000101111010010100000011000101100101010100000011010101010001010001110110010101100110011010010011001001000100010011010101000001010100011001100101010001001100001101010101001101001100

如果我们要证明自己是中本聪，则需拿创世区块地址签名，最终验证“我是中本聪”则拿“创世区块挖矿的地址+原消息+签名”即可验证
# 实验代码
    import random
    a=110001010000010011000101111010010100000011000101100101010100000011010101010001010001110110010101100110011010010011001001000100010011010101000001010100011001100101010001001100001101010101001101001100
    # 求最大公约数
    def gcd(a, b):
        if a < b:
            return gcd(b, a)
        elif a % b == 0:
            return b
        else:
            return gcd(b, a % b)

    # 快速幂+取模
    def power(a, b, c):
        ans = 1
        while b != 0:
            if b & 1:
                ans = (ans * a) % c
            b >>= 1
            a = (a * a) % c
        return ans
    
    # 快速幂
    def quick_power(a: int, b: int) -> int:
        ans = 1
        while b != 0:
            if b & 1:
                ans = ans * a
            b >>= 1
            a = a * a
        return ans

    # 大素数检测
    def Miller_Rabin(n):
        a = random.randint(2, n - 2)  # 随机第选取一个a∈[2,n-2]
        # print("随机选取的a=%lld\n"%a)
        s = 0  # s为d中的因子2的幂次数。
        d = n - 1
        while (d & 1) == 0:  # 将d中因子2全部提取出来。
            s += 1
            d >>= 1

        x = power(a, d, n)
        for i in range(s):  # 进行s次二次探测
            newX = power(x, 2, n)
            if newX == 1 and x != 1 and x != n - 1:
                return False  # 用二次定理的逆否命题，此时n确定为合数。
            x = newX

        if x != 1:  # 用费马小定理的逆否命题判断，此时x=a^(n-1) (mod n)，那么n确定为合数。
            return False

        return True  # 用费马小定理的逆命题判断。能经受住考验至此的数，大概率为素数。

    # 卢卡斯-莱墨素性检验
    def Lucas_Lehmer(num: int) -> bool:  # 快速检验pow(2,m)-1是不是素数
        if num == 2:
            return True
        if num % 2 == 0:
            return False
        s = 4
        Mersenne = pow(2, num) - 1  # pow(2, num)-1是梅森数
        for x in range(1, (num - 2) + 1):  # num-2是循环次数，+1表示右区间开
            s = ((s * s) - 2) % Mersenne
        if s == 0:
            return True
        else:
            return False

    # 扩展的欧几里得算法，ab=1 (mod m), 得到a在模m下的乘法逆元b
    def Extended_Eulid(a: int, m: int) -> int:
        def extended_eulid(a: int, m: int):
            if a == 0:  # 边界条件
                return 1, 0, m
            else:
                x, y, gcd = extended_eulid(m % a, a)  # 递归
                x, y = y, (x - (m // a) * y)  # 递推关系，左端为上层
                return x, y, gcd  # 返回第一层的计算结果。
            # 最终返回的y值即为b在模a下的乘法逆元
            # 若y为复数，则y+a为相应的正数逆元

        n = extended_eulid(a, m)
        if n[1] < 0:
            return n[1] + m
        else:
            return n[1]

    # 按照需要的bit来生成大素数
    def Generate_prime(key_size: int) -> int:
        while True:
            num = random.randrange(quick_power(2, key_size - 1), quick_power(2, key_size))
            if Miller_Rabin(num):
                return num
    
    # 生成公钥和私钥
    def KeyGen(p: int, q: int):
        n = p * q
        #e = a
        e=random.randint(1, (p - 1) * (q - 1))
        while gcd(e, (p - 1) * (q - 1)) != 1:
            e = random.randint(1, (p - 1) * (q - 1))
        d = Extended_Eulid(e, (p - 1) * (q - 1))
        return n, e, d

    def Sign(x: int, d: int, n: int) -> int:
        s = power(x, d, n)
        return s

    def Verify(s: int, e: int, n: int) -> int:
        x_ = power(s, e, n)
        return x_
    
    if __name__ == '__main__':
        key_size = 136
        p = Generate_prime(key_size)
        print('p:',p)    
        q = Generate_prime(key_size)
        print('q:', q)
        n, e, d = KeyGen(p, q)

        # 消息
        x = int(input("Message: "))
        if type(x) != int:
            raise ValueError("Must be an integer!")
        # 签名
        s = Sign(x, d, n)
        # # 验证
        # x_ = Verify(s, e, n)
        # Valid = (x_ == x)
        #
        # # Attack
        # s_ = random.randint(1, (p - 1) * (q - 1))
        # m_ = random.randint(1, (p - 1) * (q - 1))
        #Output
        print("Private Key: ")
        print("N: ", n)
        print("d: ", d)
        print("Public Key: ")    
        print("N: ", n)
        print("e: ", e)
        print("Signature: ")
        print("s: ", s)

# 实验截图
![merkle树](https://user-images.githubusercontent.com/109722365/181865686-7dc6650a-8ec2-4d3d-a7a5-64ade628484a.png)

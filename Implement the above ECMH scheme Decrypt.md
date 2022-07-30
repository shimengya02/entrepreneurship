# Implement the above ECMH scheme Decrypt
# 实验思路
ECMH即把哈希映射成椭圆曲线上的点，然后利用ECC的加法。
先把集合里的元素映射成椭圆曲线上的点，然后利用椭圆曲线上的加法求解哈希值。
为达到相同的安全性，ECMH算法需要的密钥长度远远小于哈希求和算法，因而ECMH相较哈希求和算法更为安全。

# 实验代码
    import math
    import random
    from gmssl import sm3, func
    
    # 求余数
    def Mod(a, b):   
        if math.isinf(a):
            return float('inf')
        else:
            return a % b
            
      # 点加函数
    def pANDq(P, Q, a, p):
        if (math.isinf(P[0]) or math.isinf(P[1])) and (~math.isinf(Q[0]) and ~math.isinf(Q[1])):  # OP = P
            R = Q
        elif (~math.isinf(P[0]) and ~math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):  # PO = P
            R = P
        elif (math.isinf(P[0]) or math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):  # OO = O
            R = [float('inf'), float('inf')]
        else:
            if P != Q:
                l = Mod_Decimal(Q[1] - P[1], Q[0] - P[0], p)
            else:
                l = Mod_Decimal(3 * P[0] ** 2 + a, 2 * P[1], p)
            x = Mod(l ** 2 - P[0] - Q[0], p)
            y = Mod(l * (P[0] - x) - P[1], p)
            R = [x, y]
        return R
        
     # 倍点函数
    def kp(k, P, a, p): 
        k_b = bin(k).replace('0b', '')
        i = len(k_b) - 1
        R = P
        if i > 0:
            k = k - 2 ** i
            while i > 0:
                R = pANDq(R, R, a, p)
                i -= 1
            if k > 0:
                R = pANDq(R, kp(k, P, a, p), a, p)
        return R
        
     # 小数模幂
    def Mod_Decimal(n, d, b): 
        if d == 0:
            x = float('inf')
        elif n == 0:
            x = 0
        else:
            a = bin(b - 2).replace('0b', '')
            y = 1
            i = 0
            while i < len(a):
                y = (y ** 2) % b  # 快速指数运算
                if a[i] == '1':
                    y = (y * d) % b
                i += 1
            x = (y * n) % b
        return x

    def generate_key(a, p, n, G):
        sk = random.randint(1, n - 2)
        pk = kp(sk, G, a, p)
        return sk, pk
        
    # 判断是否为二次剩余
    def Legendre(n, p):  
        return pow(n, (p - 1) // 2, p)
        
    # Tonelli-Shanks算法求二次剩余
    def Tonelli_Shanks(n, p):  
        assert Legendre(n, p) == 1
        if p % 4 == 3:
            return pow(n, (p + 1) // 4, p)
        q = p - 1    
        s = 0
        while q % 2 == 0:
            q = q // 2
            s += 1
        for z in range(2, p):
            if Legendre(z, p) == p - 1:
                c = pow(z, q, p)
                break
        r = pow(n, (q + 1) // 2, p)
        t = pow(n, q, p)
        m = s
        if t % p == 1:
            return r
        else:
            i = 0
            while t % p != 1:
                temp = pow(t, 2 ** (i + 1), p)
                i += 1
                if temp % p == 1:
                    b = pow(c, 2 ** (m - i - 1), p)
                    r = r * b % p
                    c = b * b % p
                    t = t * c % p
                    m = i
                    i = 0
            return r
    
    # 定义集合的哈希
    def MultiHash(sett):  
        digest_value = [float("inf"), float("inf")]
        for i in sett:
            x = int(sm3.sm3_hash(func.bytes_to_list(i)), 16)
            temp = Mod(x ** 2 + a * x + b, p)
            y = Tonelli_Shanks(temp, p)
            digest_value = pANDq(digest_value, [x, y], a, p)
        return digest_value
    n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

    set1 = (b'chuangxin',)
    set2 = (b'chuangxin',b'chuangxin')
    set3 = (b'chuangxin', b'202000460054')
    set4 = (b'202000460054', b'chuangxin')
    result1 = MultiHash(set1)
    result2 = MultiHash(set2)
    result3 = MultiHash(set3)
    result4 = MultiHash(set4)
    print("hash(set1) = ", result1)
    print("hash(set2) = ", result2)
    print("hash(set3) = ", result3)
    print("hash(set4) = ", result4)

# 实验截图
![ECMH](https://user-images.githubusercontent.com/109722365/181916242-d38f4340-6449-43ec-a5fc-5162e82a872d.png)


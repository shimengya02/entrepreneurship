# SM3——Birthday attack
# 实验思路
将随机生成的随机数（生成的可以转换成）转成比特类型的，然后将这个比特串加密，通过对比特定长度的字符串就可以实现生日攻击，其实是遍历的思想
    from gmssl import sm3, func
    import random
    
    #byte转字符串
    def bytetostr(byte):  
        length = len(byte)
        str = b""
        for i in range(length):
            str += b'%c' % byte[i]
        return str.decode('utf-8')
    
    #字符串转换成byte
    def strtobyte(str):  
        length = len(str)
        mbyte = []
        mbytearray = str.encode('utf-8')
        for i in range(length):
            mbyte.append(mbytearray[i])
        return mbyte
 
    #在一千次循环中，将随机生成的x和y从字符串转换成比特，然后借助gssml库中的sm3哈希加密，然后通过比较前8bit进行生日攻击
    for j in range(0,1000):
        for i in range(0,2**16):
            x = strtobyte(str(random.randint(0,2**256)))
            y = strtobyte(str(random.randint(0,2**256)))
            xstr = sm3.sm3_hash(func.bytes_to_list(x))
            ystr = sm3.sm3_hash(func.bytes_to_list(y))
            if(xstr[0:8] ==ystr[0:8]):
                print("True")
                print(x),print(y)
        print("计数器:",j)
    
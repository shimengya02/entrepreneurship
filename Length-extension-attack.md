# Length-extension-attack
# 实验完成人
姓名：时梦雅

学号：202000460054
# 运行指导
可以直接运行
# 实验思路
SM3的消息长度是64字节或者它的倍数，如果消息的长度不足则需要padding。在padding时，首先填充一个1，随后填充0，直到消息长度为56(或者再加整数倍的64)字节，最后8字节用来填充消息的长度。

在SM3函数计算时，首先对消息进行分组，每组64字节，每一次加密一组，并更新8个初始向量(初始值已经确定)，下一次用新向量去加密下一组，以此类推。我们可以利用这一特性去实现攻击。当我们得到第一次加密后的向量值时，再人为构造一组消息用于下一次加密，就可以在不知道secret的情况下得到合法的hash值，这是因为8个向量中的值便能表示第一轮的加密结果。
# 实验步骤
1.随机生成一个消息(secret)，用SM3函数算出hash值(hash1)

2.生成一个附加消息(m')。首先用hash1推算出这一次加密结束后8个向量的值，再以它们作为初始向量，去加密m’，得到另一个hash值(hash2)

3.计算secret + padding + m'的hash值(hash3)，如果攻击成功，hash2应该和hash3相等
# 实验代码
    from gmssl import sm3, func
    import random
    import struct
    import binascii
    from math import ceil
    from gmssl import func
    #这里都是利用的gmssl库函数

    IV = [
        1937774191, 1226093241, 388252375, 3666478592,
        2842636476, 372324522, 3817729613, 2969243214,
    ]

    T_j = [
        2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
    ]

    #以下为头文件new_sm3中的内容，直接放到下面了，类似于一个头文件
    def sm3_ff_j(x, y, z, j):
        if 0 <= j and j < 16:
            ret = x ^ y ^ z
        elif 16 <= j and j < 64:
            ret = (x & y) | (x & z) | (y & z)
        return ret

    def sm3_gg_j(x, y, z, j):
        if 0 <= j and j < 16:
            ret = x ^ y ^ z
        elif 16 <= j and j < 64:
            #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
            ret = (x & y) | ((~ x) & z)
        return ret

    def sm3_p_0(x):
        return x ^ (func.rotl(x, 9 % 32)) ^ (func.rotl(x, 17 % 32))

    def sm3_p_1(x):
        return x ^ (func.rotl(x, 15 % 32)) ^ (func.rotl(x, 23 % 32))

    def sm3_cf(v_i, b_i):
        w = []
        for i in range(16):
            weight = 0x1000000
            data = 0
            for k in range(i*4,(i+1)*4):
                data = data + b_i[k]*weight
                weight = int(weight/0x100)
            w.append(data)

        for j in range(16, 68):
            w.append(0)
            w[j] = sm3_p_1(w[j-16] ^ w[j-9] ^ (func.rotl(w[j-3], 15 % 32))) ^ (func.rotl(w[j-13], 7 % 32)) ^ w[j-6]
            str1 = "%08x" % w[j]
        w_1 = []
        for j in range(0, 64):
            w_1.append(0)
            w_1[j] = w[j] ^ w[j+4]
            str1 = "%08x" % w_1[j]

        a, b, c, d, e, f, g, h = v_i

        for j in range(0, 64):
            ss_1 = func.rotl(
                ((func.rotl(a, 12 % 32)) +
                e +
                (func.rotl(T_j[j], j % 32))) & 0xffffffff, 7 % 32
            )
            ss_2 = ss_1 ^ (func.rotl(a, 12 % 32))
            tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
            tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
            d = c
            c = func.rotl(b, 9 % 32)
            b = a
            a = tt_1
            h = g
            g = func.rotl(f, 19 % 32)
            f = e
            e = sm3_p_0(tt_2)

            a, b, c, d, e, f, g, h = map(
                lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])

        v_j = [a, b, c, d, e, f, g, h]
        return [v_j[i] ^ v_i[i] for i in range(8)]

    def sm3_hash(msg, new_v):
        # print(msg)
        len1 = len(msg)
        reserve1 = len1 % 64
        msg.append(0x80)
        reserve1 = reserve1 + 1
        # 56-64, add 64 byte
        range_end = 56
        if reserve1 > range_end:
            range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])

    group_count = round(len(msg) / 64) - 1

    B = []
    for i in range(0, group_count):
        B.append(msg[(i + 1)*64:(i+2)*64])

    V = []
    V.append(new_v)
        for i in range(0, group_count):
            V.append(sm3_cf(V[i], B[i]))

        y = V[i+1]
        result = ""
        for i in y:
            result = '%s%08x' % (result, i)
        return result

    def sm3_kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
        klen = int(klen)
        ct = 0x00000001
        rcnt = ceil(klen/32)
        zin = [i for i in bytes.fromhex(z.decode('utf8'))]
        ha = ""
        for i in range(rcnt):
            msg = zin  + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf8'))]
            ha = ha + sm3_hash(msg)
            ct += 1
        return ha[0: klen * 2]

    #以上为new_sm3里的内容，相当于头文件

    note = str(random.random())
    note_hash = sm3.sm3_hash(func.bytes_to_list(bytes(note, encoding='utf-8')))  #求随机生成的这个字符串的哈希值
    note_len = len(note)    #求这个随机字符串的长度
    append_message = "shimengya"   #附加消息
    str1 = ""
    list1 = []
    
    def generate_guess_hash(old_hash, note_len, append_message):
        vectors = []
        message = ""
        # 将old_hash分组，每组8个字节, 并转换为整数
        for r in range(0, len(old_hash), 8):
            vectors.append(int(old_hash[r:r + 8], 16))
        # 伪造消息
        if note_len > 64:
            for i in range(0, int(note_len / 64) * 64):
                message += 'a'
        for i in range(0, note_len % 64):
            message += 'a'
        message = func.bytes_to_list(bytes(message, encoding='utf-8'))
        message = padding(message)
        message.extend(func.bytes_to_list(bytes(append_message, encoding='utf-8')))
        return sm3_hash(message, vectors)


    def padding(msg):
        mlen = len(msg)
        msg.append(0x80)
        mlen += 1
        tail = mlen % 64
        range_end = 56
        if tail > range_end:
            range_end = range_end + 64
        for i in range(tail, range_end):
            msg.append(0x00)
        bit_len = (mlen - 1) * 8
        msg.extend([int(x) for x in struct.pack('>q', bit_len)])
        for j in range(int((mlen - 1) / 64) * 64 + (mlen - 1) % 64, len(msg)):
            global list1
            list1.append(msg[j])
            global str1
            str1 += str(hex(msg[j]))
        return msg

    guess_hash = generate_guess_hash(note_hash, note_len, append_message)
    new_msg = func.bytes_to_list(bytes(note, encoding='utf-8'))
    new_msg.extend(list1)
    new_msg.extend(func.bytes_to_list(bytes(append_message, encoding='utf-8')))
    new_msg_str = note + str1+ append_message

    new_hash = sm3.sm3_hash(new_msg)

    print("note: "+note)
    print("附加消息:", append_message)
    print("new message: \n" + new_msg_str)
    print("note hash:" + note_hash)
    print("hash(new note):" + new_hash)
    print("guess hash:" + guess_hash)

    if new_hash == guess_hash:
        print("长度扩展攻击成功")
    else:
        print("长度扩展攻击失败")
    
 
 # 实验截图
 ![长度扩展攻击](https://user-images.githubusercontent.com/109722365/181798234-331b5f78-e24b-4645-b798-58fb7492bdbd.png)

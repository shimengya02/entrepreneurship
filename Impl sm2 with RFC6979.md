# 实验题目
Impl sm2 with RFC6979
# 实验思路
基于椭圆曲线算法，在椭圆曲线里面k值(用于签名)是要严格保密的，所以利用RFC6979（确定性签名算法）来生成k
# 实验步骤
1.利用RFC4979，计算椭圆曲线上的点，生成随机数k

2.借助私钥和公钥进行加解密

3.对比加解密结果
# 实验代码
    import hashlib
    import hmac
    from gmssl import sm2,func
    import sys

    #RFC4979中生成随机数k
    if sys.version[0] == '2':
        safe_ord = ord
    else:
        safe_ord = lambda x: x
        
    def bytes_to_int(x):
        o = 0
        for b in x:
            o = (o << 8) + safe_ord(b)
        return o
        
    def deterministic_generate_k(msghash, priv):
        v = b'\x01' * 32
        k = b'\x00' * 32
        k = hmac.new(k, v+b'\x00'+priv+msghash, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        k = hmac.new(k, v+b'\x01'+priv+msghash, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        return bytes_to_int(hmac.new(k, v, hashlib.sha256).digest())
        
    i="123"
    i_sha = hashlib.sha256(i.encode('utf-8')).digest()
    i_priv=i.encode(encoding="utf8",errors="strict")
    k=deterministic_generate_k(i_sha,i_priv)
    print(k)
    #---RFC4979中生成随机数k------
    # print(str(hex(k)[2:66]))

    #16进制的公钥和私钥
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)    
    #数据和加密后数据为bytes类型
    data = b"shimengya"
    enc_data = sm2_crypt.encrypt(data)
    dec_data =sm2_crypt.decrypt(enc_data)
    print(enc_data)
    print(dec_data)
    if(dec_data == data):
      print("加解密一致")
    data = b"111" # bytes类型
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    priv_And_k=random_hex_str
    sign = sm2_crypt.sign(data,priv_And_k) #  16进制    
    if(sm2_crypt.verify(sign, data)): #  16进制
      print("验证签名成功")

# 实验截图
![RFC6979](https://user-images.githubusercontent.com/109722365/181920443-15e2f4b7-3206-4fa4-a1dd-9f477634c13a.png)

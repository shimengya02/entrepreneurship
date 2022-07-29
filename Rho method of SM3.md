# Rho method of SM3
# 实验思路
# 实验步骤
# 实验代码
    from gmssl import sm3, func
    
    def bytetostr(byte):  # byte转字符串
        length = len(byte)
        str1 = b""
        for i in range(length):
            str1 += b'%c' % byte[i]
        return str1.decode('utf-8')

    def strtobyte(str):  # 字符串转换成byte
        length = len(str)
        mbyte = []
        mbytearray = str.encode('utf-8')
        for i in range(length):
            mbyte.append(mbytearray[i])
        return mbyte
    
    Rho=set()
    count=1
    x=1
    for c in range(1,100):
      while(count):
        for i in range(0,2**16):
          y=(x*x)+c #生成函数
          x=y
          ybyte=strtobyte(str(y))
          ysec = sm3.sm3_hash(func.bytes_to_list(ybyte))[0:2] #SM3加密
          if(ysec in Rho):
            print("i是",i,"c是",c)
            print("找到的碰撞长度为",(c-1)*(2**16)+i)
            count=0
            break
          else:
            Rho.add(ysec)
            
# 实验截图

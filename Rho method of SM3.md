# Rho method of SM3
# 实验思路
在0与m-1之间随即选取2个数a,b:
若m没有真因子则出现 a=b(mod m) 的情况只有一种即a=b的情况；
而m有真因子的g的话 a=b(mod g) 的情况有(m-1)/g种；
那么我们用一个函数产生一系列随机数，假设这个函数是 f(x)=(x*x+1)%c;第k个随机数 r(k)=f(r(k-1))+1;对一个和数c取模
则会产生一系列不同c的同余系（rho形状，如下图所示），但是他虽然不和c同余，但是也许会和c的因子g同余。

![R-C](https://user-images.githubusercontent.com/109722365/181915228-146258bc-7094-4cb9-834b-bc6b819c355f.png)

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

# 实验项目
SM4 speed up
# 实验完成人
姓名：时梦雅

学号：202000460054
# 运行指导
可以直接运行
# 算法描述
SM4 的密钥长度和分组长度均为 128 比特，加密算法与密钥扩展算法都采用32 轮非平衡 Feistel 结构，加解密算法相同，区别在于轮密钥使用顺序相反。

![明文](https://user-images.githubusercontent.com/109722365/182006908-19044725-d5eb-4697-9c72-1ef543715736.png)

# 优化方法
### 为了方便展示，我先在word上面注释好了再截图过来的
### 1. 多线程
![多线程](https://user-images.githubusercontent.com/109722365/182006996-3ce8e2b9-b627-4201-b5b6-d4ffe28fcf7d.png)
### 2.循环展开
![循环展开](https://user-images.githubusercontent.com/109722365/182007052-7d1b806a-1f8a-45ee-beff-84be332cde6f.png)
### 3.查表优化
![查表](https://user-images.githubusercontent.com/109722365/182007067-e016b5dc-7080-413b-b852-1f98189b1edd.png)

# 实验代码
    #include <iostream>
    #include <cstring>
    #include <Windows.h>
    #include <thread>
    using namespace std;
    const int maxnum = 1000000;
    uint32_t secretkey[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    uint32_t plaintext[maxnum][4] = { 0 };
    uint32_t secrettext[maxnum][4];
    uint32_t rkey[32];
    uint32_t X[maxnum][36];
    uint32_t num = 0xFFFFFFFF;
    unsigned char Sbox[16][16] =
    {
        {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
        {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
        {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
        {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
        {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
        {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
        {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
        {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
        {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},    
        {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
        {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
        {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
        {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
        {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
        {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
        {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48} };
    uint32_t Fk[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
    uint32_t Ck[32] = { 0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
                       0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                       0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
                       0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                       0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
                       0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                       0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                       0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 };
    uint32_t T(uint32_t x)
    {
        uint8_t s[4];
        uint32_t res = 0;
        for (int i = 0; i < 4; i=i+4)
        { 
            s[i] = x >> (24 - i* 8);
            s[i] = Sbox[s[i] >> 4][s[i] & 0x0f];
            res |= s[i] << (24 - i* 8);

            s[i+1] = x >> (24 - (i+1) * 8);
            s[i+1] = Sbox[s[i+1] >> 4][s[i+1] & 0x0f];
            res |= s[i+1] << (24 - (i+1) * 8);

            s[2] = x >> (24 - 2 * 8);
            s[2] = Sbox[s[2] >> 4][s[2] & 0x0f];
            res |= s[2] << (24 - 2 * 8);

            s[3] = x >> (24 - 3 * 8);
            s[3] = Sbox[s[3] >> 4][s[3] & 0x0f];
            res |= s[3] << (24 - 3 * 8);
        }
        return res ^ (((res << 2) | (res >> 30)) & num) ^ (((res << 10) | (res >> 22)) & num) ^ (((res << 18) | (res >> 14)) & num) ^ (((res << 24) | (res >> 8)) & num);
    }
    uint32_t T1(uint32_t x)
    {
        uint8_t s[4];
        uint32_t res = 0;
        for (int i = 0; i < 4; i=i+2)
        {
    
            s[i] = x >> (24 - i * 8);
            s[i] = Sbox[s[i] >> 4][s[i] & 0x0f];
            res |= s[i] << (24 - i * 8);

            s[i+1] = x >> (24 - (i+1) * 8);
            s[i+1] = Sbox[s[i+1] >> 4][s[i+1] & 0x0f];
            res |= s[i+1] << (24 - (i+1) * 8);
           /* s[i + 2] = x >> (24 - (i + 2) * 8);
            s[i + 2] = Sbox[s[i + 2] >> 4][s[i +2] & 0x0f];
            res |= s[i + 2] << (24 - (i + 2) * 8);

            s[i + 3] = x >> (24 - (i + 3) * 8);
            s[i + 3] = Sbox[s[i + 3] >> 4][s[i + 3] & 0x0f];
            res |= s[i + 3] << (24 - (i + 3) * 8);*/
        
        }
        return res ^ (((res << 13) | (res >> 19)) & num) ^ (((res << 23) | (res >> 9)) & num);
    }
    void key()
    {
        uint32_t k[36];
        memset(k, 0, sizeof(k));
        for (int i = 0; i < 4; i=i+2)
        {
            k[i] = secretkey[i] ^ Fk[i];
            k[i+1] = secretkey[i+1] ^ Fk[i+1];
        }
        for (int i = 0; i < 32; i=i+2)
        {
            k[i + 4] = k[i] ^ T1(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ Ck[i]);
            rkey[i] = k[i + 4];
            k[i + 5] = k[i + 1] ^ T1(k[i + 2] ^ k[i + 3] ^ k[i + 4] ^ Ck[i + 1]);
            rkey[i+1] = k[i + 5];
            /*k[i + 6] = k[i + 2] ^ T1(k[i + 3] ^ k[i + 4] ^ k[i + 5] ^ Ck[i + 2]);
            rkey[i+2] = k[i + 6];
            k[i + 7] = k[i+3] ^ T1(k[i + 4] ^ k[i + 5] ^ k[i + 6] ^ Ck[i+3]);
            rkey[i+3] = k[i + 3];*/
        }
    }
    void solve(int num, int i)    
    {
        for (int a = i * maxnum / 8; a < (i + 1) * maxnum / 8; a++)
        {
            for (int i = 0; i < 4; i=i+2)
            {
                X[a][i] = plaintext[a][i];
                X[a][i+1] = plaintext[a][i+1];
            }
            for (int i = 0; i < 32; i=i+4)
            {
                X[a][i + 4] = X[a][i] ^ T(X[a][i + 1] ^ X[a][i + 2] ^ X[a][i + 3] ^ rkey[i]);
                X[a][i + 5] = X[a][i+1] ^ T(X[a][i + 2] ^ X[a][i + 3] ^ X[a][i + 4] ^ rkey[i+1]);
                X[a][i + 6] = X[a][i + 2] ^ T(X[a][i + +3] ^ X[a][i + 4] ^ X[a][i + 5] ^ rkey[i + 2]);
                X[a][i + 7] = X[a][i+3] ^ T(X[a][i + 4] ^ X[a][i + 5] ^ X[a][i + 6] ^ rkey[i+3]);
            }
            for (int i = 0; i < 4; i=i+2)
            {
                secrettext[a][i] = X[a][35 - i];
       、       secrettext[a][i+1] = X[a][34 - i];
            }
        }    
    }
    int main()
    {
        thread t[8];
        double run_time;
        LARGE_INTEGER time_start; //开始时间
        LARGE_INTEGER time_over;  //结束时间    
        double dqFreq;            //计时器频率
        LARGE_INTEGER f;          //计时器频率
        QueryPerformanceFrequency(&f);
        dqFreq = (double)f.QuadPart;
        QueryPerformanceCounter(&time_start);
        key();
        for (int i = 0; i < 8; i=i+1)
        {
            t[i] = thread(solve, i * maxnum / 8, i);
            /*t[i+1] = thread(solve, (i+1) * maxnum / 8, i+1);*/
        }
        for (int i = 0; i < 8; i=i+1)
        {
            t[i].join();
           /* t[i+1].join();
            t[i + 2].join();
            t[i+3].join();*/
        }
        QueryPerformanceCounter(&time_over); //计时结束
        run_time = 1000 * (time_over.QuadPart - time_start.QuadPart) / dqFreq;
        cout << "run time is: " << run_time << " ms" << endl;
    }
# 实验截图
### 优化前
![优化前](https://user-images.githubusercontent.com/109722365/182007587-42187670-28c3-4c0e-9c5e-cd02dcdbaa6c.png)
### 优化后
![优化后](https://user-images.githubusercontent.com/109722365/182007591-98450ca2-11e0-4e5e-a887-eb7616241773.png)

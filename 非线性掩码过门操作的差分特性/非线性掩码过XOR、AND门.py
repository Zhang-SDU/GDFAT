"""
非线性掩码过XOR门、AND门的差分传播特性
"""

def ENCODE(x, ra, rb):
    return [ra, rb, ra & rb ^ x]


def DECODE(a, b, c):
    return a & b ^ c


def Refresh(mask, randnum):
    ma = randnum[0] & (mask[1] ^ randnum[2])
    mb = randnum[1] & (mask[0] ^ randnum[2])
    rc = ma ^ mb ^ ((randnum[0] ^ randnum[2]) & (randnum[1] ^ randnum[2])) ^ randnum[2]
    a = mask[0] ^ randnum[0]
    b = mask[1] ^ randnum[1]
    c = mask[2] ^ rc
    return [a, b, c]


def EvalAND(mask1, mask2, rand1, rand2):
    mask11 = Refresh(mask1, rand1)
    mask22 = Refresh(mask2, rand2)
    ma = (mask11[1] & mask22[2]) ^ (rand1[2] & mask22[1])
    md = (mask11[2] & mask22[1]) ^ (rand2[2] & mask11[1])
    x = (mask11[0] & mask22[1]) ^ rand2[2]
    y = (mask11[1] & mask22[0]) ^ rand1[2]
    z = (mask11[0] & ma) ^ (mask22[0] & md) ^ (rand1[2] & rand2[2]) ^ (mask11[2] & mask22[2])
    return [x, y, z]


def EvalXOR(mask1, mask2, rand1, rand2):
    mask1 = Refresh(mask1, rand1)
    mask2 = Refresh(mask2, rand2)
    x = mask1[0] ^ mask2[0]
    y = mask1[1] ^ mask2[1]
    z = mask1[2] ^ mask2[2] ^ (mask1[0] & mask2[1]) ^ (mask1[1] & mask2[0])
    return [x, y, z]


# x AND y的DDT评估
DDT_AND = [[0] * 2 for _ in range(64)]
# 遍历输入
for a in range(0, 2):
    for b in range(0, 2):
        for c in range(0, 2):
            for d in range(0, 2):
                for e in range(0, 2):
                    for f in range(0, 2):
                        mask1 = [a, b, c]
                        mask2 = [d, e, f]
                        # 遍历输入差分
                        for a1 in range(0, 2):
                            for b1 in range(0, 2):
                                for c1 in range(0, 2):
                                    for d1 in range(0, 2):
                                        for e1 in range(0, 2):
                                            for f1 in range(0, 2):
                                                diff_input = a1 * 32 + b1 * 16 + c1 * 8 + d1 * 4 + e1 * 2 + f1 * 1
                                                mask1_1 = [a ^ a1, b ^ b1, c ^ c1]
                                                mask2_2 = [d ^ d1, e ^ e1, f ^ f1]
                                                # 遍历随机数
                                                for ra in range(0, 2):
                                                    for rb in range(0, 2):
                                                        for rc in range(0, 2):
                                                            for rd in range(0, 2):
                                                                for re in range(0, 2):
                                                                    for rf in range(0, 2):
                                                                        result = EvalAND(mask1, mask2, [ra, rb, rc],
                                                                                         [rd, re, rf])
                                                                        result1 = EvalAND(mask1_1, mask2_2,
                                                                                          [ra, rb, rc],
                                                                                          [rd, re, rf])
                                                                        result = DECODE(result[0], result[1], result[2])
                                                                        result1 = DECODE(result1[0], result1[1], result1[2])
                                                                        # diff = [result[0] ^ result1[0],
                                                                        #         result[1] ^ result1[1],
                                                                        #         result[2] ^ result1[2]]
                                                                        # diff_output = diff[0] * 4 + diff[1] * 2 + diff[
                                                                        #     2] * 1
                                                                        diff_output = result ^ result1
                                                                        DDT_AND[diff_input][diff_output] += 1

print("x AND y的DDT:\n")
print("      0       1\n")
for i in range(64):
    print(i, ':', end="")
    for j in range(2):
        print(str(DDT_AND[i][j] / pow(2, 12)).center(7, ' '), end=" ")
    print("\n")


# x XOR y的DDT评估
DDT_XOR = [[0] * 2 for _ in range(64)]
# 遍历输入
for a in range(0, 2):
    for b in range(0, 2):
        for c in range(0, 2):
            for d in range(0, 2):
                for e in range(0, 2):
                    for f in range(0, 2):
                        mask1 = [a, b, c]
                        mask2 = [d, e, f]
                        # 遍历输入差分
                        for a1 in range(0, 2):
                            for b1 in range(0, 2):
                                for c1 in range(0, 2):
                                    for d1 in range(0, 2):
                                        for e1 in range(0, 2):
                                            for f1 in range(0, 2):
                                                diff_input = a1 * 32 + b1 * 16 + c1 * 8 + d1 * 4 + e1 * 2 + f1 * 1
                                                mask1_1 = [a ^ a1, b ^ b1, c ^ c1]
                                                mask2_2 = [d ^ d1, e ^ e1, f ^ f1]
                                                # 遍历随机数
                                                for ra in range(0, 2):
                                                    for rb in range(0, 2):
                                                        for rc in range(0, 2):
                                                            for rd in range(0, 2):
                                                                for re in range(0, 2):
                                                                    for rf in range(0, 2):
                                                                        result = EvalXOR(mask1, mask2, [ra, rb, rc],
                                                                                         [rd, re, rf])
                                                                        result1 = EvalXOR(mask1_1, mask2_2,
                                                                                          [ra, rb, rc],
                                                                                          [rd, re, rf])
                                                                        result = DECODE(result[0], result[1], result[2])
                                                                        result1 = DECODE(result1[0], result1[1],
                                                                                         result1[2])
                                                                        # diff = [result[0] ^ result1[0],
                                                                        #         result[1] ^ result1[1],
                                                                        #         result[2] ^ result1[2]]
                                                                        # diff_output = diff[0] * 4 + diff[1] * 2 + diff[
                                                                        #     2] * 1
                                                                        diff_output = result ^ result1
                                                                        DDT_XOR[diff_input][diff_output] += 1

print("\n\nx XOR y的DDT:\n")
print("      0       1\n")
for i in range(64):
    print(i, ':', end="")
    for j in range(2):
        print(str(DDT_XOR[i][j] / pow(2, 12)).center(7, ' '), end=" ")
    print("\n")

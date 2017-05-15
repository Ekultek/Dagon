import array
import struct
from sboxes import t1, t2, t3, t4

def tiger_round(a,b,c,x,mul):
    c ^= x
    c &= 0xffffffffffffffff
    a -= t1[((c) >> (0*8))&0xFF] ^ t2[((c) >> ( 2*8)) & 0xFF] ^ t3[((c) >> (4*8))&0xFF] ^ t4[((c) >> ( 6*8)) & 0xFF]
    b += t4[((c) >> (1*8))&0xFF] ^ t3[((c) >> ( 3*8)) & 0xFF] ^ t2[((c) >> (5*8))&0xFF] ^ t1[((c) >> ( 7*8)) & 0xFF]
    b *= mul
    a &= 0xffffffffffffffff
    b &= 0xffffffffffffffff
    c &= 0xffffffffffffffff
    return {"a": a, "b":b, "c": c}

def tiger_pass(a,b,c,mul, mystr):
    values = tiger_round(a,b,c, mystr[0], mul)
    values = tiger_round(values["b"], values["c"], values["a"],mystr[1],mul)
    values = { "b": values["a"], "c": values["b"], "a": values["c"] }
    values = tiger_round(values["c"], values["a"], values["b"], mystr[2], mul)
    values = { "c": values["a"], "a": values["b"], "b": values["c"] }
    values = tiger_round(values["a"], values["b"], values["c"],mystr[3],mul)
    values = tiger_round(values["b"], values["c"], values["a"],mystr[4],mul)
    values = { "b": values["a"], "c": values["b"], "a": values["c"] }
    values = tiger_round(values["c"], values["a"], values["b"],mystr[5],mul)
    values = { "c": values["a"], "a":values["b"], "b": values["c"] }
    values = tiger_round(values["a"], values["b"], values["c"],mystr[6],mul)
    values = tiger_round(values["b"], values["c"], values["a"],mystr[7],mul)
    values = { "b": values["a"], "c":values["b"], "a": values["c"]}
    return values

def tiger_compress(str, res):
    #setup
    a = res[0]
    b = res[1]
    c = res[2]
    
    x = []

    for j in range(0,8):
        x.append(struct.unpack('Q', str[j*8:j*8+8])[0])

    # compress
    aa = a
    bb = b
    cc = c
    allf = 0xFFFFFFFFFFFFFFFF
    for i in range(0, 3):
        if i != 0:
            x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5)&allf ) & allf
            x[1] ^= x[0]
            x[2] = (x[2] + x[1]) & allf
            x[3] = (x[3] - (x[2] ^ (~x[1]&allf) << 19)&allf) & allf
            x[4] ^= x[3]
            x[5] = (x[5] + x[4]) & allf
            x[6] = (x[6] - (x[5] ^ (~x[4]&allf) >> 23)&allf) & allf
            x[7] ^= x[6]
            x[0] = (x[0] + x[7]) & allf
            x[1] = (x[1] - (x[0] ^ (~x[7]&allf) << 19)&allf) & allf
            x[2] ^= x[1]
            x[3] = (x[3] + x[2]) & allf
            x[4] = (x[4] - (x[3] ^ (~x[2]&allf) >> 23)&allf) & allf
            x[5] ^= x[4] 
            x[6] = (x[6] + x[5]) & allf
            x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF)&allf ) & allf

        if i == 0:
            vals = tiger_pass(a,b,c,5, x)
            a = vals['a']
            b = vals['b']
            c = vals['c']
        elif i == 1:
            vals = tiger_pass(a,b,c,7, x)
            a = vals['a']
            b = vals['b']
            c = vals['c']
        else:
            vals = tiger_pass(a,b,c,9, x)
            a = vals['a']
            b = vals['b']
            c = vals['c']
        tmpa = a
        a = c
        c = b
        b = tmpa
    a ^= aa
    b = (b - bb) & allf
    c = (c + cc) & allf

    # map values out
    res[0] = a
    res[1] = b
    res[2] = c

def hash(str):
    i = 0

    res = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187]
    offset = 0
    length = len(str)
    while i < length-63:
        tiger_compress( str[i:i+64], res )
        i += 64
    temp = array.array('c', str[i:])
    j = len(temp)
    temp.append(chr(0x01))
    j += 1
    
    while j&7 != 0:
        temp.append(chr(0))
        j += 1

    if j > 56:
        while j < 64:
            temp.append(chr(0))
            j += 1
        tiger_compress(temp, res)
        j = 0

    # make the first 56 bytes 0
    temp.extend([chr(0) for i in range(0, 56-j)])
    while j < 56:
        temp[j] = chr(0)
        j += 1
    while len(temp) > 56:
        temp.pop(56)

    temp.fromstring(struct.pack('Q', length<<3))
    tiger_compress(temp, res)
    
    return "%016X%016X%016X" % (res[0], res[1], res[2])

# These tests can be run using nosetests

import tiger
    
def round_helper(a, b, c, x, mul, new_a,new_b,new_c):
    ret_values = tiger.tiger_round(a, b, c, x, mul)

    assert ret_values["a"] == new_a, \
       "a failed: " + str(ret_values["a"]) + " != " + str(new_a) + "\n"
    assert ret_values["c"] == new_c, \
        "c failed: " + str(ret_values["c"]) + " != " + str(new_c) + "\n" 
    assert ret_values["b"] == new_b, \
        "b failed: " + str(ret_values["b"]) + " != " + str(new_b) + "\n"

def test_tiger_round():
    round_helper(13065445776871430898,17855811585246249540,518233413090174763, \
        12311797252403697916,7, \
        4821272432160810520,17424479681440429243,12532788606137106391)

def test_tiger_round2():
    round_helper(6280199717849618378, 8343645101657805456, 5997044206234503415,\
        12062177936022666431, 9, \
        11604645957211426640, 3986339792283275959, 17608143266212181064)

def test_tiger_round3():
    round_helper(11604645957211426640,3986339792283275959,17608143266212181064,\
        11490956213547313652, 9, \
        6441804261801137295,13333871996800360137,7720474646982516156)


"""
Results from reference:
A: 6280199717849618378
B: 8343645101657805456
C: 5997044206234503415
mul: 9
x0: 12062177936022666431
x1: 11490956213547313652
x2: 16829172008830410301
x3: 11899344311637024046
x4: 3757253942274655973
x5: 17835857420906997132
x6: 10787740079658512390
x7: 17590610739856314589
new A: 1509595445172618351
new B: 206383248218352883
new C: 2725617220977123037

"""
def test_tiger_pass():
    a =  6280199717849618378
    b =  8343645101657805456
    c =  5997044206234503415
    mul = 9
    data = [12062177936022666431, 11490956213547313652, 16829172008830410301, \
        11899344311637024046,  3757253942274655973, 17835857420906997132, \
        10787740079658512390,  17590610739856314589]

    ret_values = tiger.tiger_pass(a, b, c, mul, data)

    assert ret_values["a"] == 1509595445172618351, \
        "a failed, " + str(ret_values["a"]) + " != 1509595445172618351"
    assert ret_values["b"] == 206383248218352883, \
        "b failed, " + str(ret_values["b"]) + " != 206383248218352883"
    assert ret_values["c"] ==  2725617220977123037, \
        "c failed, " + str(ret_values["c"]) + " != 2725617220977123037"


def test_tiger_compress():
    # input data for tiger_compress must be 64 bytes long
    x = "TigerTigerTigerTigerTigerTigerTigerTigerTigerTigerTigerTigerTige"
    res = [ 81985529216486895, 18364758544493064720, 17336226011405279623]

    tiger.tiger_compress(x, res)
    assert res[0] == 0x29CCDEE812891C0F, \
        "r1 failed, %X != 0x29CCDEE812891C0F" % res[0]
    assert res[1] == 0xA18BA64634ACD11A, \
        "r2 failed, %X != 0xA18BA64634ACD11A" % res[1]
    assert res[2] == 0x5FA4D4854FCE7BCA, \
        "r3 failed, %X != 0x5FA4D4854FCE7BCA" % res[2]

# The following are the test hashes provided by the example C implementation
def test_tiger_hash():
    assert tiger.hash('') == '24F0130C63AC933216166E76B1BB925FF373DE2D49584E7A'
    assert tiger.hash('abc') == \
        'F258C1E88414AB2A527AB541FFC5B8BF935F7B951C132951'
    assert tiger.hash('Tiger') == \
        '9F00F599072300DD276ABB38C8EB6DEC37790C116F9D2BDF'
    assert tiger.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01" \
        "23456789+-") == '87FB2A9083851CF7470D2CF810E6DF9EB586445034A5A386'
    assert tiger.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+" \
        "0123456789") == '467DB80863EBCE488DF1CD1261655DE957896565975F9197'
    assert tiger.hash("Tiger - A Fast New Hash Function, by Ross Anderson and" \
        " Eli Biham") == '0C410A042968868A1671DA5A3FD29A725EC1E457D3CDB303'
    assert tiger.hash("Tiger - A Fast New Hash Function, by Ross Anderson and" \
        " Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.") == \
        'EBF591D5AFA655CE7F22894FF87F54AC89C811B6B0DA3193'
    assert tiger.hash("Tiger - A Fast New Hash Function, by Ross Anderson and" \
        " Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 19" \
        "96.") == '3D9AEB03D1BD1A6357B2774DFD6D5B24DD68151D503974FC'
    assert tiger.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01" \
        "23456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345" \
        "6789+-") == '00B83EB4E53440C576AC6AAEE0A7485825FD15E70A59FFE4'
      
 

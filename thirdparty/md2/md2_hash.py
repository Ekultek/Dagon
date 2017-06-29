#! /usr/bin/env python

"""
An implementation of the MD2 message digest algorithm, as specified in RFC 1319 (corrected for the reported erratum). The API is pretty much the same as in the standard md5 module.

(c) 2006 Tom Anderson <twic@urchin.earth.li>

Redistribution and use in source and binary forms, with or without modification, are permitted.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""

digest_size = 16


def pad(buf, size):
    n = size - len(buf)
    return buf + ([n] * n)


S = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
    98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
    30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
    190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
    169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
    128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
    255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
    79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
    69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
    27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
    85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
    44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
    106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
    242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
    49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20]


def checksum_errant(c, buf):  # without erratum applied
    l = c[-1]
    for i in xrange(digest_size):
        l = S[(buf[i] ^ l)]
        c[i] = l


def checksum(c, buf):
    l = c[-1]
    for i in xrange(digest_size):
        l = S[(buf[i] ^ l)] ^ c[i]
        c[i] = l


def digest(d, buf):
    for i in xrange(digest_size):
        b = buf[i]
        d[(i + digest_size)] = b
        d[(i + (2 * digest_size))] = b ^ d[i]
    t = 0
    for n in xrange(18):  # 18 rounds
        for i in xrange((3 * digest_size)):
            t = d[i] ^ S[t]
            d[i] = t
        t = (t + n) & 0xff


HEX = "0123456789abcdef"


def hexch(b):
    return HEX[((b >> 4) & 0xf)] + HEX[(b & 0xf)]


def hexstr(bytes):
    return "".join(map(hexch, bytes))


class MD2(object):
    """Works exactly like an md5 object.

    """

    def __init__(self, m=None):
        self.digest_size = digest_size
        self.buf = []
        self.c = [0] * digest_size
        self.d = [0] * (3 * digest_size)
        if (m != None):
            self.update(m)

    def update(self, m):
        # todo: direct handling of 16-byte chunks with large enough inputs (len(m) >= (digest_size - len(buf)), then len(m_remaining) >= digest_size)
        # but also handle values of m which do not respond to len or indexing, eg byte iterators
        for ch in m:
            self.buf.append(ord(ch))
            if (len(self.buf) == digest_size):
                self.updateblock(self.buf)
                del self.buf[:]

    def updateblock(self, buf):
        checksum(self.c, buf)
        digest(self.d, buf)

    def digest(self):
        buf = pad(self.buf, self.digest_size)
        c = list(self.c)
        checksum(c, buf)
        #print "*** checksum after padding = ", hexstr(c)
        d = list(self.d)
        digest(d, buf)
        digest(d, c)
        return d[0:16]

    def hexdigest(self):
        return hexstr(self.digest())

    def copy(self):
        copy = MD2()
        copy.buf = list(self.buf)
        copy.c = self.c
        copy.d = self.d
        return copy


def new(m=None):
    """Creates a new MD2 object, with an optional initial argument."""
    return MD2(m)


def md2(m):
    """Computes the MD2 digest of a message."""
    return MD2(m).digest()


def md2h(m):
    """Computes the MD2 digest of a message, and returns as a hex string."""
    return MD2(m).hexdigest()


def readchars(f):
    """Returns an iteration over the characters in a file."""
    while True:
        b = f.read(1)
        if (b == ""): return
        yield b


def printmd2(name, f):
    print(md2h(readchars(f)) + "\t" + name)  # compatible with python 3.x


"""TEST_VECTORS = {
    "": "8350e5a3e24c153df2275c9f80692773",
    "a": "32ec01ec4a6dac72c0ab96fb34c0b5d1",
    "abc": "da853b0d3f88d99b30283a69e6ded6bb",
    "message digest": "ab4f496bfb2a530b219ff33031fe06b0",
    "abcdefghijklmnopqrstuvwxyz": "4e8ddff3650292ab5a4108c3aa47940b",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "da33def2a42df13975352846c30338cd",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "d5976f79d83d3a0dc9806c3c66f3efd8"
}

if (__name__ == "__main__"):
    # act like md5sum
    import sys

    if (len(sys.argv) == 1):
        printmd2("-", sys.stdin)
    else:
        for filename in sys.argv[1:]:
            if (filename == "-x"):
                for s in sorted(TEST_VECTORS.keys(), key=len):
                    d = md2h(s)
                    print "MD2 (\"%s\") = %s" % (s, d)
                # assert d == TEST_VECTORS[s], s
                continue
            f = file(filename)
            printmd2(filename, f)
            f.close()"""
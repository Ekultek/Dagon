import base64
import binascii
import hashlib
import os
import random
import zlib
import string as _string

import sha3
import bcrypt
from thirdparty.blake import blake
from thirdparty.des import pydes
from thirdparty.md2 import md2_hash
from thirdparty.tiger import tiger

import lib
from custom import _crc64 as _crc64


def mysql_hash(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a hash identical to the one that MySQL uses

      > :param string: string to turn into MySQL hash
      > :param salt: for all occurrences, given salt to be provided
      > :param front: for all occurrences, salt goes on the front if True
      > :param back: for all occurrences, salt goes on the back if True
      > :return: a MySQL hash

      Example:
        >>> mysql_hash("test")
        *94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    if salt is not None and front and not back:
        obj1 = hashlib.sha1(salt + string).digest()
        obj2 = hashlib.sha1(obj1).hexdigest()
    elif salt is not None and back and not front:
        obj1 = hashlib.sha1(string + salt).digest()
        obj2 = hashlib.sha1(obj1).hexdigest()
    else:
        obj1 = hashlib.sha1(string).digest()
        obj2 = hashlib.sha1(obj1).hexdigest()
    return "*{}".format(obj2.upper())


def oracle_10g(string, salt=None, iv="\0" * 8, padding="\0", key="0123456789ABCDEF", **placeholder):
    """
      Create a Oracle 10g hash, if no salt is given (username) a random salt will be generated

      > :param string: string to hash
      > :param iv: IV for the encryption
      > :param padding: padding for the encryption
      > :param key: cipher key
      > :return: a hashed password

      Example:
        >>> oracle_10g("test")
        5CFC9D5BE82D37A2
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    if salt is None:
        salt = lib.settings.random_salt_generator(use_string=True)[0]
    constr = "".join("\0{}".format(c for c in (string + salt).upper()))
    cipher = pydes.des(key.decode("hex"), IV=iv, pad=padding)
    encrypt = cipher.encrypt(constr)[-8:]
    cipher = pydes.des(encrypt, mode=1, IV=iv, pad=padding)
    encrypt = cipher.encrypt(constr)
    return encrypt[-8:].encode("hex").upper()


def oracle_11g(string, salt=None, **placeholder):
    """
      Create a Oracle 11g hash, if no salt is provided, salt will be created

      > :param string: string to be hashed
      > :param salt_size: the size of the salt to be used
      > :return: an 11g Oracle hash

      Example
        >>> oracle_11g("test")
        S:1F5298FFB092EF6543B2ECB52D9F6AA9B2162FA06258684A784165746E6D
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    if salt is None:
        salt = lib.settings.random_salt_generator(use_string=True, length=10)[0]

    obj = hashlib.sha1()
    obj.update(string + salt)
    return "s:{}{}".format(obj.hexdigest(), salt.encode("hex")).upper()


def blowfish(string, **placeholder):
    """
      Create a blowfish hash using bcrypt

      > :param string: string to generate a Blowfish hash from
      > :return: Blowfish hash

      Example:
        >>> blowfish("test")
        $2b$12$fSX/dvlx3dJGkGYKSbBbLOTOhzqj8xQ2krOtu2QkHNeJiYTC0B/ji
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    return bcrypt.hashpw(str(string), bcrypt.gensalt())


def postgres(string, salt=None, **placeholder):
    """
      Create a PostgreSQL hash, if no salt is provided, salt will be created

      > :param string: string to be hashed
      > :return: a PostgreSQL hash

      Example:
        >>> postrges("test", "testing")
        md55d6685f9c56cdd04d635c7cbed612db3
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    if salt is None:
        salt = lib.settings.random_salt_generator(use_string=True)[0]
    obj = hashlib.md5()
    obj.update(string + salt)
    data = obj.hexdigest()
    return "md5{}".format(data)


def mssql_2000(string, salt=None, **placeholder):
    """
      Create a MsSQL 2000 hash from a given string, if no salt is given, random salt will be generated

      > :param string: the string to hash
      > :return: a MsSQL 2000 hash

      Example
        >>> mssql_2000("testpass", salt="testsalt")
        0x01007465737473616C74C74B43A2862ECC89C7F94E02583583377F03977A11E46AC5D5F599D31D0D6078958AF1D73C64FEA9
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    obj1 = hashlib.sha1()
    obj2 = hashlib.sha1()
    if salt is None:
        salt = lib.settings.random_salt_generator(use_string=True)[0]
    crypt_salt = salt.encode("hex")
    data_string = "".join(map(lambda s: ("%s\0" if ord(s) < 256 else "%s") % s.encode("utf8"), string))
    obj1.update(data_string + crypt_salt)
    obj2.update(data_string.upper() + salt)
    hash_val = "0100{}{}{}".format(crypt_salt, obj1.hexdigest(), obj2.hexdigest())
    return "0x{}".format(hash_val.upper())


def mssql_2005(string, salt=None, **placeholder):
    """
      Create an MsSQL 2005 hash, if not salt is given, salt will be created

      > :param string: string to be hashed
      > :return: a MsSQL 2005 hash

      Example:
        >>> mssql_2005("test", salt="testing")
        0x010074657374696e673f0414438c1b692da8be7a1211a76d314ea0210f
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    if salt is None:
        salt = lib.settings.random_salt_generator(use_string=True)[0]
    data_string = "".join(map(lambda s: ("%s\0" if ord(s) < 256 else "%s") % s.encode("utf8"), string))
    obj = hashlib.sha1()
    obj.update(data_string + salt)
    hash_data = obj.hexdigest()
    return "0x0100{}{}".format(salt.encode("hex"), hash_data)


def ripemd160(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a RipeMD160 hash from a given string

      > :param string: string to be hashed
      > :return: a hashed string with or without salt

      Example:
        >>> ripemd160("test")
        5e52fee47e6b070565f74372468cdc699de89107
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    obj = hashlib.new("ripemd160")
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def blake224(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a Blake224 hash from given string

      > :param string: string to be hashed
      > :return: a blake224 hash

      Example:
        >>> blake224("test")
        e9543bfe985642bc30d41903161b2252a014deca64a9af27fc0c111f
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    obj = blake.BLAKE(224)
    if salt is not None and front and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back and not front:
        digest = obj.hexdigest(string + salt)
    else:
        digest = obj.hexdigest(string)
    return digest


def blake256(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a Blake256 hash from a given string

      > :param string: string to be hashed
      > :return: a blake256 hash

      Example:
        >>> blake256("test")
        dc1ef7d25c8658590f3498d15baa87834f39a6208ddcb28fdfb7cc3179b8bf8f
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    obj = blake.BLAKE(256)
    if salt is not None and front and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back and not front:
        digest = obj.hexdigest(string + salt)
    else:
        digest = obj.hexdigest(string)
    return digest


def blake384(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a bBlake384 hash from a given string

      > :param string: string to be hashed
      > :return: a blake384 hash

      Example:
        >>> blake384("test")
        97c456fb92567f27324497d1d41a8427eed77a1f3a1161faf49e40ebae44a7d1e2f9e8bdf7bc193ae9e37bebf50ece76
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    obj = blake.BLAKE(384)
    if salt is not None and front and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back and not front:
        digest = obj.hexdigest(string + salt)
    else:
        digest = obj.hexdigest(string)
    return digest


def blake512(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a Blake512 hash from a given string

      > :param string: string to be hashed
      > :return: a blake512 hash

      Example:
        >>> blake512("test")
        042d11c84ee88718f4451b05beb21c0751e243ed15491a927fef891ba0ba17bbe0d2f5286639cebabe86d876e4064821cd9d5764faba5bbd3d63d02275c0593e
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    obj = blake.BLAKE(512)
    if salt is not None and front and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back and not front:
        digest = obj.hexdigest(string + salt)
    else:
        digest = obj.hexdigest(string)
    return digest


def md2(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an MD2 hash from a given string

      > :param string: string to be hashed
      > :return: an MD2 hash

      Example:
        >>> md2("test")
        dd34716876364a02d0195e2fb9ae2d1b
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    if salt is not None and front and not back:
        obj = md2_hash.md2h(salt + string)
    elif salt is not None and back and not front:
        obj = md2_hash.md2h(string + salt)
    else:
        obj = md2_hash.md2h(string)
    return obj


def md4(string, salt=None, front=False, back=False, **placeholder):
    """
    Create an MD4 hash from a given string

      > :param string: string to hash
      > :return: a MD4 hash

      Example:
        >>> md4("test")
        db346d691d7acc4dc2625db19f9e3f52
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)

    obj = hashlib.new("md4")
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def md5_crypt(string, salt=None, magic="$1$", **placeholder):
    """
      Create an MD5 crypt hash

      > :param string: string to be hashed
      > :param magic: the magic header of the hash `$1$`
      > :return: an MD5 crypt hash

      Example:
        >>> md5_crypt("test", salt="12345")
        $1$12345$uVW.jhvKKr8H/P/g4Hsj21
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    if salt is None:
        salt = lib.settings.random_salt_generator(use_string=True)[0]
    seedchars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    unix_format = "{}{}${}"
    obj = hashlib.md5()
    obj1 = hashlib.md5()
    obj2 = hashlib.md5()

    string = str(string)  # take care of any unicode errors that come up

    def __to64(v, n):
        retval = ''
        while n - 1 >= 0:
            n -= 1
            retval += seedchars[v & 0x3f]
            v = v >> 6
        return retval

    if salt[:len(magic)] == magic:
        salt = salt[len(magic):]
    salt = _string.split(salt, '$', 1)[0]
    salt = salt[:8]
    ctx = string + magic + salt
    obj.update(string + salt + string)
    final = obj.digest()
    for pl in range(len(string), 0, -16):
        if pl > 16:
            ctx = ctx + final[:16]
        else:
            ctx = ctx + final[:pl]
    i = len(string)
    while i:
        if i & 1:
            ctx = ctx + chr(0)
        else:
            ctx = ctx + string[0]
        i = i >> 1
    obj1.update(ctx)
    final = obj1.digest()
    for i in range(1000):
        ctx1 = ''
        if i & 1:
            ctx1 = ctx1 + string
        else:
            ctx1 = ctx1 + final[:16]

        if i % 3:
            ctx1 = ctx1 + salt

        if i % 7:
            ctx1 = ctx1 + string

        if i & 1:
            ctx1 = ctx1 + final[:16]
        else:
            ctx1 = ctx1 + string
        obj2.update(ctx1)
        final = obj2.digest()
    passwd = ''
    passwd = passwd + __to64((int(ord(final[0])) << 16)
                             | (int(ord(final[6])) << 8)
                             | (int(ord(final[12]))), 4)

    passwd = passwd + __to64((int(ord(final[1])) << 16)
                             | (int(ord(final[7])) << 8)
                             | (int(ord(final[13]))), 4)

    passwd = passwd + __to64((int(ord(final[2])) << 16)
                             | (int(ord(final[8])) << 8)
                             | (int(ord(final[14]))), 4)

    passwd = passwd + __to64((int(ord(final[3])) << 16)
                             | (int(ord(final[9])) << 8)
                             | (int(ord(final[15]))), 4)

    passwd = passwd + __to64((int(ord(final[4])) << 16)
                             | (int(ord(final[10])) << 8)
                             | (int(ord(final[5]))), 4)

    passwd = passwd + __to64((int(ord(final[11]))), 2)

    return unix_format.format(magic, salt, passwd)


def md5(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an MD5 hash from a given string

      > :param string: string to be hashed
      > :return: a MD5 hash

      Example:
        >>> md5("test")
        098f6bcd4621d373cade4e832627b4f6
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.md5()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def half_md5(string, salt=None, front=False, back=False, posx="", **placeholder):
    """
      Create half of an MD5 hash

      > :param string: string to be hashed
      > :param posx: position to return
      > :return: half an MD5 hash

      Example:
        >>> half_md5("test")
        098f6bcd4621d373
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.md5()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)

    # Return the position specified
    if posx == "left":
        return obj.hexdigest()[:16]
    elif posx == "right":
        return obj.hexdigest()[16:]
    elif posx == "mid":
        return obj.hexdigest()[8:-8]
    else:
        # Randomly return a half MD5 string
        return random.choice([obj.hexdigest()[:16], obj.hexdigest()[8:-8], obj.hexdigest()[16:]])


def md5_pass_salt(string, salt=None, **placeholder):
    """
      Create an MD5 password in a specific salting order $md5(md5($pass)+md5($salt))

      > :param string: string to get hashed
      > :return: a hashed password in $md5(md5($pass)+md5($salt)) format

      Example:
        >>> md5_pass_salt("test")
        06315beb4110dc8be4669fc68efc92ea
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    if salt is None:
        salt = lib.settings.random_salt_generator(warning=False)[0]
    obj1 = hashlib.md5()
    obj2 = hashlib.md5()
    obj3 = hashlib.md5()
    obj1.update(string)
    obj2.update(salt)
    hash1 = obj1.hexdigest()
    hash2 = obj2.hexdigest()
    obj3.update(hash1 + hash2)
    return obj3.hexdigest()


def md5_md5_pass(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an MD5 hash in a specific order $md5(md5($pass))

      > :param string: string to be hashed
      > :return: a hashed password in md5(md5($pass)) format

      Example:
        >>> md5_md5_pass("test")
        fb469d7ef430b0baf0cab6c436e70375
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj1 = hashlib.md5()
    obj2 = hashlib.md5()
    if salt is not None and front and not back:
        obj1.update(salt + string)
    elif salt is not None and back and not front:
        obj1.update(string + salt)
    else:
        obj1.update(string)
    hash1 = obj1.hexdigest()
    obj2.update(hash1)
    return obj2.hexdigest()


def md5_md5_md5_pass(string, salt=None, **placeholder):
    """
      Create an MD5 hash in a specific format md5(md5(md5(pass)))

      > :param string: string to be hashed
      > :return: a MD5 hash in the above format

      Example
        >>> md5_md5_md5_pass("test")
        25ab3b38f7afc116f18fa9821e44d561
        >>> md5_md5_md5_pass("test", salt="0x0011")
        25ab3b38f7afc116f18fa9821e44d561:0x0011
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj1 = hashlib.md5()
    obj2 = hashlib.md5()
    obj3 = hashlib.md5()
    obj1.update(string)
    first_hash = obj1.hexdigest()
    obj2.update(first_hash)
    second_hash = obj2.hexdigest()
    obj3.update(second_hash)
    if salt is None:
        return obj3.hexdigest()
    else:
        return "{}:{}".format(obj3.hexdigest(), salt)


def md5_salt_pass_salt(string, salt=None, **placeholder):
    """
      Create a MD5 hash in a specific format md5($salt+$pass+$salt)

      > :param string: string to be hashed
      > :return: a hashed password in md5(salt+pass+salt) format

      Example:
        >>> md5_salt_pass_salt("test", salt="1234")
        4d4f7f073a628fc11ba04f58793bb106
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    if salt is None:
        salt = lib.settings.random_salt_generator(warning=False)[0]
    split_by = int(round(len(salt) / 2))
    obj1 = hashlib.md5()
    obj1.update(salt[0:split_by] + string + salt[-split_by:])
    return obj1.hexdigest()


def ssha(string, salt=None, **placeholder):
    """
      Create an SSHA hash (seeded salted sha)

      > :param string: string to be hashed
      > :return: a hashed string

      Example:
        >>> ssha("test")
        {SSHA}icUtMxBSzwPv_dSBvwPEwXyK4lo=
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    if salt is None:
        salt = os.urandom(4)
    obj = hashlib.sha1()
    obj.update(string)
    obj.update(salt)
    return "{SSHA}" + base64.urlsafe_b64encode(obj.digest() + salt)


def sha1(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an SHA1 hash from a given string

      > :param string: string to be hashed
      > :return: a SHA1 hashed string

      Example:
        >>> sha1("test")
        a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.sha1()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def half_sha1(string, salt=None, front=False, back=False, posx="", **placeholder):
    """
      Create half of an SHA1 hash

      > :param string: string to be hashed
      > :return: half an SHA1 hash

      Example:
        >>> half_sha1("test")
        a94a8fe5ccb19ba61c4c
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.sha1()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)

    if posx == "left":
        return obj.hexdigest()[:20]
    elif posx == "right":
        return obj.hexdigest()[20:]
    elif posx == "mid":
        return obj.hexdigest()[10:-10]
    else:
        placement_opts = ["left", "right", "mid"]
        return half_sha1(string, salt=salt, front=front, back=back, posx=random.choice(placement_opts))


def sha1_rounds(string, rounds=10, salt=None, front=False, back=False, **placeholder):
    """
      Create a SHA1 hash in given rounds, meaning re-hexdigest the hash with a already created
      hash value

      > :param string: string to be hashed
      > :param rounds: how many rounds the digest should go
      > :return: a hashed string

      Example:
        >>> sha1_rounds("test", rounds=3)
        84cb15079fe0d9e19e01a8526f9602be9fa10e3c
        >>> sha1_rounds("test", rounds=1000)
        2d69bdd6464a76fa735656b77e1869c626e9af8c
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.sha1()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
        hashed = obj.hexdigest()
    for _ in range(int(rounds) + 1):
        obj1 = hashlib.sha1()
        obj1.update(hashed)
        hashed = obj1.hexdigest()
    return hashed


def sha224(string, salt=None, front=False, back=False, **placeholder):
    """
       Create a SHA224 hash from a given string

      > :param string: string to be hashed
      > :return: an SHA224 hash

      Example:
        >>> sha224("test")
        90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.sha224()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha256(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an SHA256 hash from a given string

      > :param string: string to be hashed
      > :return: a SHA256 hash

      Example:
        >>> sha256("test")
        9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.sha256()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha384(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an SHA384 hash from a given string

      > :param string:
      > :return:

      Example:
        >>> sha384("test")
        768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = hashlib.sha384()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha512(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an SHA512 hash from a given string

      > :param string: string to be hashed
      > :return: an SHA512 hash

      Example:
        >>> sha512("test")
        ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    obj = hashlib.sha512()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha3_224(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a SHA3 224 hash from a given string

      > :param string: string to be hashed
      > :return: an SHA3 224 hash

      Example:

        >>> sha3_224("test")
        3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    obj = sha3.sha3_224()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha3_256(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a SHA3 256 hash from a given string

      > :param string: string to be hashed
      > :return: SHA3 256 hash

      Example:
        >>> sha3_256("test")
        36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    obj = sha3.sha3_256()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha3_384(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a SHA3 384 hash from a given string

      > :param string: string to hash
      > :return: SHA3 384 hash

      Example:
        >>> sha3_384("test")
        e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    obj = sha3.sha3_384()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha3_512(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an SHA3 512 hash from a given string

      > :param string: string to be hashed
      > :return: SHA3 512 hash

      Example
        >>> sha3_512("test")
        9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
        if type(string) is unicode:
            string = lib.settings.force_encoding(string)
    obj = sha3.sha3_512()
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def whirlpool(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a WHIRLPOOL hash from a given string

      > :param string: string to be hashed
      > :return: a WHIRLPOOL hash

      Example:
        >>> whirlpool("test")
        b913d5bbb8e461c2c5961cbe0edcdadfd29f068225ceb37da6defcf89849368f8c6c2eb6a4c4ac75775d032a0ecfdfe8550573062b653fe92fc7b8fb3b7be8d6
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    obj = hashlib.new("whirlpool")
    if salt is not None and front and not back:
        obj.update(salt + string)
    elif salt is not None and back and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def tiger192(string, salt=None, front=False, back=False, **placeholder):
    """
      Hash a password using Tiger192

      > :param string: string to be hashed into Tiger192
      > :return: a Tiger192 hash

      Example:
        >>> tiger192("test")
        8d1fd829fc83b37af1e5ba697ce8680d1d8bc430d76682f1
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    if salt is not None and front and not back:
        obj = tiger.hash(salt + string)
    elif salt is not None and back and not front:
        obj = tiger.hash(string + salt)
    else:
        obj = tiger.hash(string)
    return obj.lower()


def crc32(string, salt=None, front=False, back=False, use_hex=False, **placeholder):
    """
      Create a CRC32 hash from a given string

      > :param string: string to be hashed
      > :return: a CRC32 hash

      Example:
        >>> crc32("test")
        d87f7e0c
        >>> crc32("test", use_hex=True)
        0xd87f7e0cL
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    if salt is not None and front and not back:
        long_int = hex(zlib.crc32(salt + string) % 2 ** 32)
    elif salt is not None and back and not front:
        long_int = hex(zlib.crc32(string + salt) % 2 ** 32)
    else:
        long_int = hex(zlib.crc32(string) % 2 ** 32)

    if not use_hex:
        return str(long_int)[2:-1]
    else:
        return long_int


def crc64(string, salt=None, front=False, back=False, use_hex=False, **placeholder):
    """
      Create a CRC64 hash from a given string

      > :param string: string to be hashed
      > :return: a CRC64 hash

      Example:
        >>> crc64("test")
        bf3d60cae58eeb8e
        >>> crc64("test", use_hex=True)
        0xbf3d60cae58eeb8eL
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    if salt is not None and front and not back:
        long_int = _crc64.crc64(salt + string)
    elif salt is not None and back and not front:
        long_int = _crc64.crc64(string + salt)
    else:
        long_int = _crc64.crc64(string)

    if not use_hex:
        return str(hex(long_int))[2:-1]
    else:
        return long_int


def ntlm(string, **placeholder):
    """
      Create an NTLM hash, identical to the one used in Windows protocol

      > :param string: string to be hashed
      > :return: a NTLM hashed string

      Example:
        >>> ntlm("test")
        0cb6948805f797bf2a82807973b89537
    """
    if type(string) is unicode:
        string = lib.settings.force_encoding(string)
    obj = hashlib.new("md4")
    obj.update(string.encode("utf-16le"))
    data = obj.digest()
    return binascii.hexlify(data)


def sha2(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("SHA2 hashes are not implemented yet.")


def scrypt_hash(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("Scrypt hashes are not implemented yet.")


def dsa(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("DSA hashes are not implemented yet.")


def wordpress(string, salt=None, itoa64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
              **placeholder):
    raise NotImplementedError("Wordpress hashes are not implemented yet.")


def haval160(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("Haval-160 hashes are not implemented yet.")


def tiger160(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("Tiger-160 hashes are not implemented yet.")

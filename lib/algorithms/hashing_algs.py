import hashlib
import random
import sha3
import lib

from passlib.hash import bcrypt, oracle11, oracle10
from thirdparty.blake import blake
from thirdparty.md2 import md2_hash
from thirdparty.tiger import tiger


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
    if salt is not None and front is True and not back:
        obj1 = hashlib.sha1(salt + string).digest()
        obj2 = hashlib.sha1(obj1).hexdigest()
    elif salt is not None and back is True and not front:
        obj1 = hashlib.sha1(string + salt).digest()
        obj2 = hashlib.sha1(obj1).hexdigest()
    else:
        obj1 = hashlib.sha1(string).digest()
        obj2 = hashlib.sha1(obj1).hexdigest()
    return "*{}".format(obj2.upper())


def wordpress(string, salt=None, **placeholder):
    raise NotImplementedError("Wordpress hashes are not implemented yet.")
    pass


def oracle_hash(string, salt=None, oracle_version=11, **placeholder):
    raise NotImplementedError("Oracle hashes are not implemented yet")
    pass


def blowfish_hash(string, salt=None, front=False, back=False):
    """
      Create a Blowfish hash using passlib

      > :param string: string to generate a Blowfish hash from
      > :return: Blowfish hash

      Example:
        >>> blowfish_hash("test")
        $2b$12$9.uNMtjZD./9xGMD3QLHpen6WBSs8TmjmYSl5EGs4OS/zsUwmJivq
    """
    if salt is not None and front is True and not back:
        return bcrypt.hash(salt + string)
    elif salt is not None and back is True and not front:
        return bcrypt.hash(string + salt)
    else:
        return bcrypt.hash(string)


def scrypt_hash(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("Scrypt hashes are not implemented yet")


def ripemd160(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a RipeMD160 hash from a given string

      > :param string: string to be hashed
      > :return: a hashed string with or without salt

      Example:
        >>> ripemd160("test")
        5e52fee47e6b070565f74372468cdc699de89107
    """
    obj = hashlib.new("ripemd160")
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = blake.BLAKE(224)
    if salt is not None and front is True and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = blake.BLAKE(256)
    if salt is not None and front is True and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = blake.BLAKE(384)
    if salt is not None and front is True and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back is True and not front:
        digest = obj.hexdigest(string + salt)
    else:
        digest = obj.hexdigest(string)
    return digest


def blake512(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a Blake512 hash from a given string

      > :param string: string to ne hashed
      > :return: a blake512 hash

      Example:
        >>> blake512("test")
        042d11c84ee88718f4451b05beb21c0751e243ed15491a927fef891ba0ba17bbe0d2f5286639cebabe86d876e4064821cd9d5764faba5bbd3d63d02275c0593e
    """
    obj = blake.BLAKE(512)
    if salt is not None and front is True and not back:
        digest = obj.hexdigest(salt + string)
    elif salt is not None and back is True and not front:
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
    if salt is not None and front is True and not back:
        obj = md2_hash.md2h(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = hashlib.new("md4")
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def md5(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an MD5 hash from a given string

      > :param string: string to be hashed
      > :return: a MD5 hash

      Example:
        >>> md5("test")
        098f6bcd4621d373cade4e832627b4f6
    """
    obj = hashlib.md5()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = hashlib.md5()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj1 = hashlib.md5()
    obj2 = hashlib.md5()
    if salt is not None and front is True and not back:
        obj1.update(salt + string)
    elif salt is not None and back is True and not front:
        obj1.update(string + salt)
    else:
        obj1.update(string)
    hash1 = obj1.hexdigest()
    obj2.update(hash1)
    return obj2.hexdigest()


def md5_salt_pass_salt(string, salt=None, **placeholder):
    """
      Create a MD5 hash in a specific format md5($salt+$pass+$salt)

      > :param string: string to be hashed
      > :return: a hashed password in md5(salt+pass+salt) format

      Example:
        >>> md5_salt_pass_salt("test", salt="1234")
        4d4f7f073a628fc11ba04f58793bb106
    """
    if salt is None:
        salt = lib.settings.random_salt_generator(warning=False)
    split_by = int(round(len(salt)/2))
    obj1 = hashlib.md5()
    obj1.update(salt[0:split_by] + string + salt[-split_by:])
    return obj1.hexdigest()


def sha1(string, salt=None, front=False, back=False, **placeholder):
    """
      Create an SHA1 hash from a given string

      > :param string: string to be hashed
      > :return: a SHA1 hashed string

      Example:
        >>> sha1("test")
        a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
    """
    obj = hashlib.sha1()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha2(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("SHA2 is not implemented yet")
    pass


def sha3_224(string, salt=None, front=False, back=False, **placeholder):
    """
      Create a SHA3 224 hash from a given string

      > :param string: string to be hashed
      > :return: an SHA3 224 hash

      Example:

        >>> sha3_224("test")
        3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b
    """
    obj = sha3.sha3_224()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = sha3.sha3_256()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = sha3.sha3_384()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = sha3.sha3_512()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def sha224(string, salt=None, front=False, back=False, **placeholder):
    """
       Create a SHA224 hash from a given string

      > :param string: string to be hashed
      > :return: an SHA224 hash

      Example:
        >>> sha224("test")
        90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809
    """
    obj = hashlib.sha224()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = hashlib.sha256()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = hashlib.sha384()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = hashlib.sha512()
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
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
    obj = hashlib.new("whirlpool")
    if salt is not None and front is True and not back:
        obj.update(salt + string)
    elif salt is not None and back is True and not front:
        obj.update(string + salt)
    else:
        obj.update(string)
    return obj.hexdigest()


def dsa(string, salt=None, front=False, back=False, **placeholder):
    raise NotImplementedError("DSA hashes are not implemented yet")


def tiger192(string, salt=None, front=False, back=False, **placeholder):
    """
      Hash a password using Tiger192

      > :param string: string to be hashed into Tiger192
      > :return: a Tiger192 hash

      Example:
        >>> tiger192("test")
        8d1fd829fc83b37af1e5ba697ce8680d1d8bc430d76682f1
    """
    if salt is not None and front is True and not back:
        obj = tiger.hash(salt + string)
    elif salt is not None and back is True and not front:
        obj = tiger.hash(string + salt)
    else:
        obj = tiger.hash(string)
    return obj.lower()


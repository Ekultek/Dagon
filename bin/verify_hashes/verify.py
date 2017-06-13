import re
from lib.settings import shutdown
from lib.settings import LOGGER
from lib.settings import DAGON_ISSUE_LINK


# Has to be the first function so I can use it in the regex
def build_re(hex_len, prefix=r"", suffix=r"(:.+)?"):
    regex_string = r"^{}[a-f0-9]{{{}}}{}$".format(prefix, hex_len, suffix)
    return re.compile(regex_string, re.IGNORECASE)


# Top: Most likely algorithm
# Bottom: Least likely algorithm (may not be implemented)
HASH_TYPE_REGEX = {
    build_re(8): [
        ("crc32", None),
        (None, None)
    ],
    build_re(20): [
        ("half sha1", None),
        (None, None)
    ],
    build_re(32): [
        ("md5", "md4", "md2", "ntlm",
         "md5(md5(pass)+md5(salt))", "md5(md5(pass))",
         "md5(salt+pass+salt)"),
        ("ripe128", "haval128",
         "tiger128", "skein256(128)", "skein512(128",
         "skype", "zipmonster", "prestashop")
    ],
    build_re(16): [
        ("half md5", None),
        (None, None)
    ],
    build_re(64): [
        ("sha256", "sha3_256"),
        ("haval256", "gost r 34.1194",
         "gost cryptopro sbox", "skein256",
         "skein512(256)", "ventrilo",
         "ripemd256")
    ],
    build_re(128): [
        ("sha512", "whirlpool", "sha3_512"),
        ("salsa10", "salsa20",
         "skein512", "skein1024(512)")
    ],
    build_re(56, suffix=""): [
        ("sha224", "sha3_224"),
        ("shein256(224)", "skein512(224)",
         "haval224")
    ],
    build_re(40): [
        ("sha1", "ripemd160", "sha1(sha1(pass))"),
        ("doublesha1", "haval160", "tiger160",
         "has160", "skein256(160)", "skein512(160)",
         "dsa")
    ],
    build_re(96, suffix=""): [
        ("sha384", "sha3_384"),
        ("skein512(384)", "skein1024(384")
    ],
    build_re(40, prefix=r"\*", suffix=""):  [
        ("mysql 5.x", "mysql 4.1")
    ],
    build_re(48, suffix=""): [
        ("tiger192", None),
        ("haval192", "sha1(oracle)", "xsha v10.4-v10.6")
    ],
    re.compile(r"^\$[\w.]{1}\$\w+\$\S{22}$", re.IGNORECASE): [
        ("wordpress", None),
        ("PHPass", "Joomla")
    ],
    re.compile(r"^\$\d\w\$\d+\$\S{53}$", re.IGNORECASE): [
        ("blowfish", None),
        (None, None)
    ],
    re.compile(r"^S:[a-zA-Z0-9]{60}$", re.IGNORECASE): [
        ("oracle", None),
        (None, None)
    ],
    re.compile(r"^[0-9a-z]{4,12}:[0-9a-f]{16,20}:[0-9a-z]{2080}$", re.IGNORECASE): [
        ("agile", None),
        (None, None)
    ],
    re.compile(r"^[0-9a-f]{64,70}:[a-f0-9]{32,40}:\d+:[a-f0-9]{608,620}$", re.IGNORECASE): [
        ("cloud", None),
        (None, None)
    ],
    re.compile(r"^\{[^{}]*}[a-zA-Z0-9][\w/-]+=?$", re.IGNORECASE): [
        ("ssha", None),
        (None, None)
    ],
    re.compile(r"^\w+:\d+:[a-z0-9]{32}:[a-z0-9]{32}:::$", re.IGNORECASE): [
        ("windows local (ntlm)", None),
        (None, None)
    ]
}


def verify_hash_type(hash_to_verify, least_likely=False):
    """
      Attempt to verify a given hash by type (md5, sha1, etc..)

      >  :param hash_to_verify: hash string
      >  :param least_likely: show least likely options as well
      >  :return: likely options, least likely options, or none

      Example:
        >>> verify_hash_type("098f6bcd4621d373cade4e832627b4f6", least_likely=True)
        [('md5', 'md4', 'md2'), ('double md5', 'lm', ... )]
    """
    for regex in HASH_TYPE_REGEX:
        if regex.match(hash_to_verify) and least_likely:
            return HASH_TYPE_REGEX[regex]
        elif regex.match(hash_to_verify) and not least_likely:
            return HASH_TYPE_REGEX[regex][0]
        else:
            pass
    error_msg = "Unable to find any algorithms to match the given hash. "
    error_msg += "If you feel this algorithm should be implemented make "
    error_msg += "an issue here: {}"
    LOGGER.fatal(error_msg.format(DAGON_ISSUE_LINK))
    shutdown(1)

import re


# Has to be the first function so I can use it in the regex
def build_re(hex_len, prefix=r"", suffix=r"(:.+)?"):
    regex_string = r"^{}[a-f0-9]{{{}}}{}$".format(prefix, hex_len, suffix)
    return re.compile(regex_string, re.IGNORECASE)


HASH_TYPE_REGEX = {
    build_re(32): [
        ("md5", "md4", "md2"),  # Most likely
        ("double md5", "lm", "ripe128", "haval128",  # Least likely
         "tiger128", "skein256(128)", "skein512(128",
         "lotus Notes/Domino 5", "skype", "zipmonster",
         "prestashop")
    ],
    build_re(64): [
        ("sha256", "sha3256"),
        ("haval256", "gost r 34.1194",
         "gost cryptopro sbox", "skein256",
         "skein512(256)", "ventrilo",
         "ripemd256")
    ],
    build_re(128): [
        ("sha512", "whirlpool"),
        ("salsa10", "salsa20", "sha3512",
         "skein512", "skein1024(512)")
    ],
    build_re(56, suffix=""): [
        ("sha224", "haval224"),
        ("sha3224", "shein256(224)",
         "skein512(224)")
    ],
    build_re(40): [
        ("sha1", "ripemd160", "dsa"),
        ("doublesha1", "haval160", "tiger160",
         "has160", "linkedin", "skein256(160)",
         "skein512(160)")
    ],
    build_re(90, suffix=""): [
        ("sha384", "sha3384"),
        ("skein512(384)", "skein1024(384")
    ],
    build_re(40, prefix=r"\*", suffix=""):  [
        ("mysql 5.x", "mysql 4.1")
    ],
    build_re(48, suffix=""): [
        ("haval192", "sha1(oracle)"),
        ("tiger192", "xsha (v10.4-v10.6)")
    ],
    re.compile(r"^\$[\w.]{1}\$\w+\$\S{22}$", re.IGNORECASE): [
        ("wordpress v4.x", "wordpress v3.x"),
        (None, None)
    ],
    re.compile(r"^\$\d\w\$\d+\$\S{53}$", re.IGNORECASE): [
        ("blowfish", None),
        (None, None)
    ],
    re.compile(r"^S:[a-zA-Z0-9]{60}$", re.IGNORECASE): [
        ("oracle", None),
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

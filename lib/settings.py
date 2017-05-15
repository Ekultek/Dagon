import re
import logging
import time
import random
import string
from colorlog import ColoredFormatter
from lib.algorithms.hashing_algs import *

# Create logging
log_level = logging.INFO
logger_format = "[%(log_color)s%(asctime)s %(levelname)s%(reset)s] %(log_color)s%(message)s%(reset)s"
logging.root.setLevel(log_level)
formatter = ColoredFormatter(logger_format, datefmt="%H:%M:%S")
stream = logging.StreamHandler()
stream.setLevel(log_level)
stream.setFormatter(formatter)
LOGGER = logging.getLogger('configlog')
LOGGER.setLevel(log_level)
LOGGER.addHandler(stream)

# Version number <major>.<minor>.<patch>.<git-commit>
VERSION = "1.0"
# Colors, green if stable, yellow if dev
TYPE_COLORS = {"dev": 33, "stable": 92}
# Version string, dev or stable release?
VERSION_STRING = "\033[92mv{}\033[0m(\033[{}m\033[1mdev\033[0m)".format(VERSION, TYPE_COLORS["dev"]) if len(
    VERSION) >= 4 else \
    "\033[92mv{}\033[0m(\033[{}m\033[1mstable\033[0m)".format(VERSION, TYPE_COLORS["stable"])
# Program saying
SAYING = "\033[30mAdvanced Hash Manipulation\033[0m"
# Clone link
CLONE = "\033[30mhttps://github.com/ekultek/dagon.git\033[0m"
# Sexy banner to display
BANNER = """\033[91m
'||''|.
 ||   ||   ....     ... .   ...   .. ...
 ||    || '' .||   || ||  .|  '|.  ||  ||
 ||    || .|' ||    |''   ||   ||  ||  ||
.||...|'  '|..'|'  '||||.  '|..|' .||. ||. [][][]
                  .|....'  \033[0m
{} ... {}
Clone: {}
""".format(SAYING, VERSION_STRING, CLONE)
# Algorithm function dict
FUNC_DICT = {
    "md2": md2, "md4": md4, "md5": md5,
    "mysql": mysql_hash, "blowfish": blowfish_hash, "oracle": oracle_hash,
    "ripemd160": ripemd160,
    "blake224": blake224, "blake256": blake256, "blake384": blake384, "blake512": blake512,
    "sha1": sha1, "sha224": sha224, "sha256": sha256, "sha384": sha384, "sha512": sha512,
    "whirlpool": whirlpool,
    "dsa": dsa,
    "tiger192": tiger192
}
# Regular expression to see if you already have a bruteforce wordlist created
WORDLIST_RE = re.compile("Dagon-bfdict-[a-zA-Z]{7}.txt")


def show_banner():
    """
      Show the banner of the program

      > :return: banner
    """
    print(BANNER)


def show_hidden_banner():
    """
      Show the hidden banner (just saying and clone)

      > :return: a hidden banner
    """
    print("\n\n{} {}\nClone: {}\n\n".format(SAYING, VERSION_STRING, CLONE))


def prompt(question, choices):
    """
      Create a prompt for the user

      > :param question: a string containing the question needed to be answered
      > :param choices: a string containing choices
      > :return: a prompt
    """
    return raw_input("[{} PROMPT] {}[{}]: ".format(time.strftime("%H:%M:%S"), question, choices))


def random_salt_generator(use_string=False, use_number=False, length=None):
    """
      Create a random string of salt to append to the beginning of a hash

      > :param use_string:
      > :param use_number:
      > :param length:
      > :return:

      Example:
        >>> random_salt_generator(use_string=True)
        fUFVsatp
    """
    if length is None:
        length = 8
    else:
        if use_string is True and not use_number:
            salt_type = "characters"
        elif use_number is True and not use_string:
            salt_type = "integers"
        else:
            salt_type = "characters and integers"
        length = int(length)

    if length > 12:
        LOGGER.warning("It is recommenced to keep salt length under 12 {} for faster hashing..".format(salt_type))
    salt = []
    placement = ["front", "back"]
    if not use_string and use_number is True:
        for _ in range(0, length):
            salt.append(str(random.randint(0, 9)))
    elif use_string is True and not use_number:
        for _ in range(0, length):
            salt.append(random.choice(string.ascii_letters))
    elif use_string is True and use_number is True:
        for _ in range(0, length):
            salt.append(random.choice(str(string.digits + string.ascii_letters)))
    else:
        LOGGER.warning("No choice given as salt, defaulting to numbers..")
        for _ in range(0, length):
            salt.append(str(random.randint(0, 9)))
    return ''.join(salt), random.choice(placement)


def match_found(data_tuple, data_sep="-" * 75, item_found="+", least_likely="-", kind="cracked", all_types=False):
    """
      Create a banner for finding a match

      > :param data_tuple: tuple containg the information required
      > :param data_sep: what to separate the information with
      > :param item_found: makes it look pretty for the items
      > :param least_likely: makes more pretty formatting for least likely hashes
    """
    if data_tuple[0][1] is None and all_types is True:
        LOGGER.warning("Only one possible type found for given hash..")
    sort_cracked = ["Clear Text: ", "Hash: ", "Tries attempted: ", "Algorithm Used: "]
    if kind == "cracked":
        print(data_sep + "\n" + "[{}] Match found:\n".format(item_found) + data_sep)
        for i, item in enumerate(sort_cracked):
            print("[{}] {}{}".format(item_found, item, data_tuple[i]))
        print(data_sep)
    else:
        if all_types is True:
            data_tuple = data_tuple[0] + data_tuple[1]
            print(data_sep + "\n" + "[{}] Most Likely Hash Type(s):\n".format(item_found) + data_sep)
            for i, _ in enumerate(data_tuple):
                if i <= 2:
                    if _ is not None:
                        print("[{}] {}".format(item_found, data_tuple[i].upper()))
                        if i == 2:
                            print(data_sep + "\n" + "[{}] Least Likely Hash Type(s):\n".format(least_likely) + data_sep)
                else:
                    if _ is not None:
                        print("[{}] {}".format(least_likely, data_tuple[i].upper()))

            print(data_sep)
        else:
            print(data_sep + "\n" + "[{}] Most Likely Hash Types:\n".format(item_found) + data_sep)
            for i, _ in enumerate(data_tuple):
                if i <= 2:
                    if _ is not None:
                        print("[{}] {}".format(item_found, data_tuple[i].upper()))
            print(data_sep)



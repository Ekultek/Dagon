import re
import sys
import logging
import time
import random
import string
import base64
import requests
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
VERSION = "1.2.4.7"
# Colors, green if stable, yellow if dev
TYPE_COLORS = {"dev": 33, "stable": 92}
# Version string, dev or stable release?
VERSION_STRING = "\033[92mv{}\033[0m(\033[{}m\033[1mdev\033[0m)".format(VERSION, TYPE_COLORS["dev"]) if len(
    VERSION) >= 4 else \
    "\033[92mv{}\033[0m(\033[{}m\033[1mstable\033[0m)".format(VERSION, TYPE_COLORS["stable"])
# Program saying
SAYING = "\033[97mAdvanced Hash Manipulation\033[0m"
# Clone link
CLONE = "\033[97mhttps://github.com/ekultek/dagon.git\033[0m"
# Homepage link
HOMEPAGE = "\033[97mhttps://ekultek.github.io/Dagon/\033[0m"
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
Home: {}
""".format(SAYING, VERSION_STRING, CLONE, HOMEPAGE)
# Algorithm function dict
FUNC_DICT = {
    "md2": md2, "md4": md4, "md5": md5, "half md5": half_md5,
    "mysql": mysql_hash, "blowfish": blowfish_hash, "oracle": oracle_hash,
    "ripemd160": ripemd160,
    "blake224": blake224, "blake256": blake256, "blake384": blake384, "blake512": blake512,
    "sha1": sha1, "sha224": sha224, "sha256": sha256, "sha384": sha384, "sha512": sha512,
    "sha3_224": sha3_224, "sha3_256": sha3_256, "sha3_384": sha3_384, "sha3_512": sha3_512,
    "whirlpool": whirlpool,
    "dsa": dsa,
    "tiger192": tiger192
}
# Regular expression to see if you already have a bruteforce wordlist created
WORDLIST_RE = re.compile("Dagon-bfdict-[a-zA-Z]{7}.txt")
# Wordlist links
WORDLIST_LINKS = [
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrL2FhODgyMDk5ZWQxYzNlZjAwNWYzYWY2ZjhmYmFhZTExL3Jhdy84ODQ4NjBhNjAzZWQ0MjE3MTgyN2E1MmE3M2VjNzAzMjNhOGExZWY5L2dpc3RmaWxlMS50eHQ=',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrLzAwNWU3OWQ2NmU2MzA2YWI0MzZjOGJmYTc1ZTRiODMwL3Jhdy8xNjY5YjNjMDFmMjRhM2Q2OTMwZDNmNDE1Mjk3ZTg5OGQ1YjY2NGUzL29wZW53YWxsXzMudHh0',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrLzE4NTBmM2EwZGNjNDE0YWZlOGM3NjYyMjBlOTYxYjE4L3Jhdy9iYWQ0NTA0NjcwY2FmM2UxNDY1NWI2ZjJlZGQ0MjJmOTJjMzI2MWI5L215c3BhY2UudHh0',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrLzBkYWU2YTI5MjgzMjcyNmE2Y2MyN2VlNmVjOTdmMTFjL3Jhdy84MWFkOWFkOWUwZjQxMmY2YjIwMTM3MDI2NDcxZGRmNDJlN2JjMjkyL2pvaG4udHh0',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrL2Q4ZjZiYjE2MGEzYzY2YzgyNWEwYWY0NDdhMDM1MDVhL3Jhdy83MWI4NmM5MGU3NDRkZjM0YzY3ODFjM2U0MmFjMThkOGM4ZjdkYjNlL2NhaW4udHh0',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrL2JmM2MwYjQwMTVlYzlkMzY4YzBlNTczNzQ0MTAzYmU1L3Jhdy9lNzBhMThmOTUwNGYwZmMyYjRhMWRmN2M0Mjg2YjcyOWUyMzQ5ODljL29wZW53YWxsXzIudHh0',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrLzQ1ZTExZDBhMzNjZGE1YjM3NDM5OGYyMDgxYjEwZWZiL3Jhdy8wNzQ1ZGMzNjFlZDU5NjJiMjNkYjUxM2FkOWQyOTNlODk0YjI0YTY0L2RjLnR4dA==',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrLzNmMzcxMWUzMDdlOGM0ZTM0MDkzYzI1OGFkN2UzZWZkL3Jhdy9hMjNiYmM3YTgxNTZhOGU5NTU3NmViYTA3MmIwZDg4ZTJmYjk1MzZiL2dtYWlsXzIudHh0',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrL2U3MzE4MGM3MGZmMzY3NDFhM2M4NzIzMDZiNTFhOTU1L3Jhdy9jODE0YjFjOTZiNGJkYzZlYTRlZDE3MmMzNDIwOTg2NTBjOTcyYWZjL2J0NC50eHQ=',
    'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2JlcnplcmswL1Byb2JhYmxlLVdvcmRsaXN0cy9tYXN0ZXIvRGljdGlvbmFyeS1TdHlsZS9NYWluRW5nbGlzaERpY3Rpb25hcnkudHh0',
    'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2RhbmllbG1pZXNzbGVyL1NlY0xpc3RzL21hc3Rlci9QYXNzd29yZHMvdHdpdHRlci1iYW5uZWQudHh0',
    'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2RhbmllbG1pZXNzbGVyL1NlY0xpc3RzL21hc3Rlci9QYXNzd29yZHMvdHVzY2wudHh0'
]


def verify_python_version():
    """
      Verify python version
    """
    current_py_version = sys.version.split(" ")[0]
    if "2.7" not in current_py_version:
        LOGGER.fatal("This application requires python 2.7.x to run, You currently have python version {}".format(current_py_version))
    else:
        pass


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


def download_rand_wordlist(b64link=random.choice(WORDLIST_LINKS)):
    """
      Download a random wordlist from some wordlists I have laying around

      > :param b64link: a base64 encoded wordlist link
    """
    filename = "Download-" + random_salt_generator(use_string=True)[0]
    LOGGER.info("Beginning download..")
    with open("{}.txt".format(filename), "a+") as wordlist:
        response = requests.get(base64.b64decode(b64link), stream=True)
        total_length = response.headers.get('content-length')
        if total_length is None:
            wordlist.write(response.content)
        else:
            start = time.time()
            downloaded = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=1024):
                downloaded += len(data)
                wordlist.write(data)
                done = int(50 * downloaded / total_length)
                sys.stdout.write("\r[\033[93m{}\033[0m{}]".format("#" * done, " " * (50-done)))
                sys.stdout.flush()
    print("")
    LOGGER.info("Download complete, saved under: {}.txt. Time elapsed: {}s".format(filename, time.time() - start))


def random_salt_generator(use_string=False, use_number=False, length=None):
    """
      Create a random string of salt to append to the beginning of a hash

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
    if data_tuple is None:
        no_alg_err = "It appears that no algorithm that can match this hash has been implemented yet. "
        no_alg_err += "If you feel that this is wrong, please make a issue regarding this, and we'll "
        no_alg_err += "see if we can get it implemented."
        LOGGER.fatal(no_alg_err)
        exit(1)
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


def update_system():
    """ Update Dagon to the newest development version """
    import subprocess
    updater = subprocess.check_output("git pull origin master")
    if "Already up-to-date." in updater:
        return 1
    elif "error" or "Error" in updater:
        return -1
    else:
        return 0


def find_func_by_identifier(identity_number):
    pass
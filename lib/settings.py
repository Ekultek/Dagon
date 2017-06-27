import re
import sys
import logging
import time
import string
import urllib2
import requests
from colorlog import ColoredFormatter
from lib.algorithms.hashing_algs import *

# Create logging
log_level = logging.DEBUG
logger_format = "[%(log_color)s%(asctime)s %(levelname)s%(reset)s] %(log_color)s%(message)s%(reset)s"
logging.root.setLevel(log_level)
formatter = ColoredFormatter(logger_format, datefmt="%H:%M:%S",
                             log_colors={
                                 "DEBUG": "cyan",
                                 "INFO": "bold,green",
                                 "WARNING": "yellow",
                                 "ERROR": "red",
                                 "CRITICAL": "bold,red"
                             })
stream = logging.StreamHandler()
stream.setLevel(log_level)
stream.setFormatter(formatter)
LOGGER = logging.getLogger('configlog')
LOGGER.setLevel(log_level)
LOGGER.addHandler(stream)

# Version number <major>.<minor>.<patch>.<git-commit>
VERSION = "1.8.11.21"
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
# Issue page
DAGON_ISSUE_LINK = "https://github.com/Ekultek/Dagon/issues/new"
# Sexy banner to display when asked for
BANNER = """\033[91m
'||''|.
 ||   ||   ....    ... .   ...   .. ...
 ||    || '' .||  ||_||  .|  '|.  ||  ||
 ||    || .|' ||   |''   ||   ||  ||  ||
.||...|'  '|..'|' '||||.  '|..|' .||. ||. [][][]
                 .|....'\033[0m
{} ... {}
Clone: {}
Home: {}
""".format(SAYING, VERSION_STRING, CLONE, HOMEPAGE)
# Algorithm function dict
FUNC_DICT = {
    "md2": md2, "md4": md4, "md5": md5, "half md5": half_md5, "md5(md5(pass)+md5(salt))": md5_pass_salt,
    "md5(md5(pass))": md5_md5_pass, "md5(salt+pass+salt)": md5_salt_pass_salt,
    "mysql": mysql_hash, "blowfish": blowfish_hash, "oracle 11g": oracle_11g, "oracle 10g": oracle_10g,
    "mssql 2005": mssql_2005, "postgresql": postrges,
    "ripemd160": ripemd160,
    "blake224": blake224, "blake256": blake256, "blake384": blake384, "blake512": blake512,
    "sha1": sha1, "sha224": sha224, "sha256": sha256, "sha384": sha384, "sha512": sha512,
    "half sha1": half_sha1, "sha1(sha1(pass))": sha1_sha1_pass, "ssha": ssha,
    "sha3_224": sha3_224, "sha3_256": sha3_256, "sha3_384": sha3_384, "sha3_512": sha3_512,
    "whirlpool": whirlpool, "crc32": crc32, "ntlm": ntlm, "windows local (ntlm)": ntlm,
    "tiger192": tiger192
}
# Identity numbers
IDENTIFICATION = {
    # MD indicators
    100: "md5", 110: "md2", 120: "md4",
    # MD special indicators
    130: "md5(md5(pass)+md5(salt))", 131: "md5(md5(pass))", 132: "half md5",
    133: "md5(salt+pass+salt)",

    # Blake indicators
    200: "blake224", 210: "blake256", 220: "blake384", 230: "blake512",

    # SHA indicators
    300: "sha1", 310: "sha224", 320: "sha256", 330: "sha384", 340: "sha512",
    400: "sha3_224", 410: "sha3_256", 420: "sha3_384", 430: "sha3_512",
    # SHA special indicators
    351: "half sha1", 352: "sha1(sha1(pass))", 353: "ssha",

    # Database and external hash indicators
    500: "blowfish", 510: "mysql", 520: "oracle 11g", 530: "oracle 10g", 540: "mssql 2005", 550: "postgresql",

    # Ripemd indicators
    600: "ripemd160",

    # Tiger indicators
    700: "tiger192",

    # Other
    800: "whirlpool", 900: "crc32", 1000: "ntlm"
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
    'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2RhbmllbG1pZXNzbGVyL1NlY0xpc3RzL21hc3Rlci9QYXNzd29yZHMvdHVzY2wudHh0',
    'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2RhbmllbG1pZXNzbGVyL1NlY0xpc3RzL21hc3Rlci9QYXNzd29yZHMvMTBfbWlsbGlvbl9wYXNzd29yZF9saXN0X3RvcF8xMDAwMDAwLnR4dA==',
    'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2RhbmllbG1pZXNzbGVyL1NlY0xpc3RzL21hc3Rlci9QYXNzd29yZHMvTGl6YXJkX1NxdWFkLnR4dA==',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrLzZjNTEzNzdhMzM5YzM4YTdiMDIwMjc3NGYyOWQ5MWUyL3Jhdy82MWM1Y2I2NWNkMTljMmI4YjNkYmY4N2EzOTFkN2NkNzcxYjZjZTljL2V4YW1wbGUuZGljdA==',
    'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Fa3VsdGVrL2Q0ODc4NWNhODAxMjcwZjc3MzI3NzY1ZDI0Y2Y2MWM4L3Jhdy9iOTg3N2ZjYmVhZGEyMjNjM2I1ZmRhMGJmNWI4YmFiMzBmNmNhNGE0L2dkaWN0LnR4dA=='
]


def start_up():
    """ Start the application """
    print("\n[*] Starting up at {}..\n".format(time.strftime("%H:%M:%S")))


def shutdown(exit_key=0):
    """ Shut down the application """
    print('\n[*] Shutting down at {}..\n'.format(time.strftime("%H:%M:%S")))
    exit(exit_key)


def verify_python_version():
    """
      Verify python version
    """
    current_py_version = sys.version.split(" ")[0]
    if "2.7" not in current_py_version:
        LOGGER.debug("This application requires python 2.7.x to run.. "
                     "You currently have python version {} installed..".format(current_py_version))
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
    print("Dagon .. {} {}\nClone: {}\n".format(SAYING, VERSION_STRING, CLONE))


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


def random_salt_generator(use_string=False, use_number=False, length=None, warning=True):
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
        if warning is True:
            LOGGER.warning("No choice given as salt, defaulting to numbers..")
        for _ in range(0, length):
            salt.append(str(random.randint(0, 9)))
    return ''.join(salt), random.choice(placement)


def match_found(data_tuple, data_sep="-" * 75, item_found="+", least_likely="-", kind="cracked", all_types=False):
    """
      Create a banner for finding a match

      > :param data_tuple: tuple containing the information required
      > :param data_sep: what to separate the information with
      > :param item_found: makes it look pretty for the items
      > :param least_likely: makes more pretty formatting for least likely hashes
    """
    if data_tuple is None:
        no_alg_err = "It appears that no algorithm that can match this hash has been implemented yet. "
        no_alg_err += "If you feel that this is wrong, please make a issue regarding this, and we'll "
        no_alg_err += "see if we can get it implemented."
        LOGGER.fatal(no_alg_err)
        shutdown(1)
    if data_tuple[0][1] is None and all_types is True:
        LOGGER.warning("Only one possible type found for given hash..")
    sort_cracked = ["Clear Text: ", "Hash: ", "Tries attempted: ", "Algorithm Used: "]
    if kind == "cracked":
        print(data_sep + "\n" + "[{}] Match found:\n".format(item_found) + data_sep)
        for i, item in enumerate(sort_cracked):
            print("[{}] {}{}".format(item_found, item, data_tuple[i].upper() if i == 3 else data_tuple[i]))
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
                            print(data_sep + "\n" +
                                  "[{}] Least Likely Hash Type(s)(possibly not be implemented):\n".format(
                                      least_likely) + data_sep)
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


def show_available_algs(show_all=False, supp="+", not_yet="-"):
    """ Show all algorithms available in the program """
    being_worked_on = ["wordpress", "scrypt", "sha2", "dsa"]
    misc_info_msg = "There are currently {} supported algorithms in Dagon. "
    misc_info_msg += "To suggest the creation of a new algorithm please go "
    misc_info_msg += "make an issue here {}"
    LOGGER.info(misc_info_msg.format(len(IDENTIFICATION), DAGON_ISSUE_LINK))
    print
    print("     ID#   Alg:")
    print("     ---   ----")
    for item in sorted(IDENTIFICATION.keys()):
        print("\033[94m[{}]\033[0m  {}   {}".format(supp, item, IDENTIFICATION[item].upper()))
    if show_all is True:
        print("\nNot implemented yet:")
        for item in sorted(being_worked_on):
            print("\033[91m[{}]\033[0m {}".format(not_yet, item.upper()))


def algorithm_pointers(pointer_identity):
    """ Point to the correct algorithm given by an identification number """
    if pointer_identity is None:
        pass
    else:
        try:
            if int(pointer_identity) in IDENTIFICATION.keys():
                return IDENTIFICATION[int(pointer_identity)]
            else:
                LOGGER.fatal("The algorithm identification number you have specified is invalid.")
                LOGGER.debug("Valid identification numbers are: {}".format(IDENTIFICATION))
        except ValueError:
            LOGGER.fatal("The algorithm identification number you have specified is invalid.")
            LOGGER.debug("Valid identification numbers are: {}".format(IDENTIFICATION))


def integrity_check(url="https://raw.githubusercontent.com/Ekultek/Dagon/master/md5sum/checksum.md5",
                    path="{}/md5sum/checksum.md5"):
    """ Check the integrity of the program """
    LOGGER.info("Checking program integrity...")
    if open(path.format(os.getcwd())).read() == urllib2.urlopen(url).read():
        pass
    else:
        checksum_fail = "MD5 sums did not match from origin master, "
        checksum_fail += "integrity check has failed, this could be because "
        checksum_fail += "there is a new version available. Please check "
        checksum_fail += "for a new version and download that ({}), or be sure "
        checksum_fail += "that you have not changed any of the applications "
        checksum_fail += "code."
        LOGGER.fatal(checksum_fail.format("https://github.com/ekultek/dagon.git"))
        shutdown(-1)

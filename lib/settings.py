import logging
import re
import string
import sys
import time
import math
import platform

import requests
from colorlog import ColoredFormatter

from lib.github.create_issue import request_connection
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
VERSION = "1.13.29.49"
# Colors, green if stable, yellow if dev
TYPE_COLORS = {"dev": 33, "stable": 92}
# Version string, dev or stable release?
if len(VERSION) >= 4:
    VERSION_STRING = "\033[92mv{}\033[0m(\033[{}m\033[1mdev\033[0m)".format(VERSION, TYPE_COLORS["dev"])
else:
    VERSION_STRING = "\033[92mv{}\033[0m(\033[{}m\033[1mstable\033[0m)".format(VERSION, TYPE_COLORS["stable"])
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
    "md5(md5(pass))": md5_md5_pass, "md5(salt+pass+salt)": md5_salt_pass_salt, "md5(md5(md5(pass)))": md5_md5_md5_pass,
    "mysql": mysql_hash, "blowfish": blowfish, "oracle 11g": oracle_11g, "oracle 10g": oracle_10g,
    "mssql 2005": mssql_2005, "postgresql": postgres, "mssql 2000": mssql_2000,
    "ripemd160": ripemd160,
    "blake224": blake224, "blake256": blake256, "blake384": blake384, "blake512": blake512,
    "sha1": sha1, "sha224": sha224, "sha256": sha256, "sha384": sha384, "sha512": sha512,
    "half sha1": half_sha1, "sha1(sha1(pass))": sha1_sha1_pass, "ssha": ssha,
    "sha1(sha1(sha1(pass)))": sha1_sha1_sha1_pass,
    "sha3_224": sha3_224, "sha3_256": sha3_256, "sha3_384": sha3_384, "sha3_512": sha3_512,
    "whirlpool": whirlpool, "crc32": crc32, "ntlm": ntlm, "windows local (ntlm)": ntlm, "crc64": crc64,
    "tiger192": tiger192
}
# Identity numbers
IDENTIFICATION = {
    # MD indicators
    100: "md5", 110: "md2", 120: "md4",
    # MD special indicators
    130: "md5(md5(pass)+md5(salt))", 131: "md5(md5(pass))", 132: "half md5",
    133: "md5(salt+pass+salt)", 134: "md5(md5(md5(pass)))",

    # Blake indicators
    200: "blake224", 210: "blake256", 220: "blake384", 230: "blake512",

    # SHA indicators
    300: "sha1", 310: "sha224", 320: "sha256", 330: "sha384", 340: "sha512",
    400: "sha3_224", 410: "sha3_256", 420: "sha3_384", 430: "sha3_512",
    # SHA special indicators
    351: "half sha1", 352: "sha1(sha1(pass))", 353: "ssha", 354: "sha1(sha1(sha1(pass)))",

    # Database and external hash indicators
    500: "blowfish", 510: "mysql", 520: "oracle 11g", 530: "oracle 10g", 540: "mssql 2005", 550: "postgresql",
    560: "mssql 2000",

    # Ripemd indicators
    600: "ripemd160",

    # Tiger indicators
    700: "tiger192",

    # Other
    800: "whirlpool", 900: "crc32", 1000: "ntlm", 1100: "crc64"
}
# Regular expression to see if you already have a bruteforce wordlist created
WORDLIST_RE = re.compile("Dagon-bfdict-[a-zA-Z]{7}.txt")


def start_up(verbose=False):
    """ Start the application """
    if not verbose:
        print("\n[*] Starting up at {}..\n".format(time.strftime("%H:%M:%S")))
    else:
        print("[*] Starting up at: {}({})..\n".format(str(time.time()), time.strftime("%H:%M:%S")))


def shutdown(exit_key=0, verbose=False):
    """ Shut down the application """
    if not verbose:
        print('\n[*] Shutting down at {}..\n'.format(time.strftime("%H:%M:%S")))
        exit(exit_key)
    else:
        print("\n[*] Shutting down at {}({})..\n".format(str(time.time()), time.strftime("%H:%M:%S")))
        exit(exit_key)


def convert_file_size(byte_size, magic_num=1024):
    """
      Convert a integer to a file size (B, KB, MB, etc..)
      > :param byte_size: integer that is the amount of data in bytes
      > :param magic_num: the magic number that makes everything work, 1024
      > :return: the amount of data in bytes, kilobytes, megabytes, etc..
    """
    byte_size = float(byte_size)
    if byte_size == 0:
        return "0B"
    # Probably won't need more then GB, but still it's good to have
    size_data_names = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    floored = int(math.floor(math.log(byte_size, magic_num)))
    pow_data = math.pow(magic_num, floored)
    rounded_data = round(byte_size / pow_data, 2)
    return "{}{}".format(rounded_data, size_data_names[floored])


def _get_install_link(system_data):
    links = {
        "windows": "https://www.python.org/ftp/python/2.7.13/python-2.7.13.msi",
        "linux": "sudo apt-get install python",
        "other": "https://www.python.org/downloads/release/python-2713/"
    }
    for item in links.keys():
        if item in system_data:
            return links[item]


def verify_python_version(verbose=False, ver_re="2.[0-9]{1,2}.[0-9]{1,3}"):  # and we're back :|
    """
      Verify python version
    """
    if verbose:
        LOGGER.debug("Verifying what version of Python you have..")
    current_py_version = sys.version.split(" ")[0]
    if not re.match(ver_re, current_py_version):
        LOGGER.fatal(
            "{filename} currently requires a Python version that is <= 2.7.x, "
            "you currently have Python version {version} installed. If you "
            "want to run {filename} please install a Python version that matches "
            "the above outlined requirements and re-run {filename}. You can download "
            "the required Python version here: {link}".format(
                version=current_py_version, filename=str(os.path.basename(__file__).split(".")[0].title()),
                link=_get_install_link(platform.platform().lower())
            )
        )


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
    try:
        return raw_input("[{} PROMPT] {}[{}]: ".format(time.strftime("%H:%M:%S"), question, choices))
    except:  # idk what the exception is, so if you know it lemme know
        return input("[{} PROMPT] {}[{}]: ".format(time.strftime("%H:%M:%S"), question, choices))


def download_rand_wordlist(verbose=False, multi=1, filepath="{}/lib/data_files/wordlist_links", dirname="downloads"):
    """
      Download a random wordlist from some wordlist_links I have laying around

      > :param b64link: a base64 encoded wordlist link
    """
    with open(filepath.format(os.getcwd())) as wordlist_links:
        if multi == 1:
            b64link = random.choice(wordlist_links.readlines())
            filename = "Download-" + random_salt_generator(use_string=True)[0]
            LOGGER.info("Beginning download..")
            create_dir(dirname, verbose=verbose)
            with open("{}/{}/{}.txt".format(os.getcwd(), dirname, filename), "a+") as wordlist:
                response = requests.get(base64.b64decode(b64link.strip()), stream=True)
                total_length = response.headers.get('content-length')
                if verbose:
                    LOGGER.debug("Content length to be downloaded: {}..".format(convert_file_size(int(total_length))))
                    LOGGER.debug("Wordlist link downloading from: '{}'..".format(b64link.strip()))
                if total_length is None:
                    wordlist.write(response.content)
                else:
                    start = time.time()
                    if verbose:
                        LOGGER.debug("Starting download at {}..".format(start))
                    downloaded = 0
                    total_length = int(total_length)
                    for data in response.iter_content(chunk_size=1024):
                        downloaded += len(data)
                        wordlist.write(data)
                        done = int(50 * downloaded / total_length)
                        sys.stdout.write("\r[\033[93m{}\033[0m{}]".format("#" * done, " " * (50-done)))
                        sys.stdout.flush()
            print("")
            LOGGER.info("Download complete, saved under: {}/{}/{}.txt. Time elapsed: {}s".format(
                os.getcwd(), dirname, filename, time.time() - start
            ))
        else:
            if multi <= len(wordlist_links.readlines()):
                for _ in range(int(multi)):
                    LOGGER.info("Downloading wordlist #{}..".format(_ + 1))
                    download_rand_wordlist(verbose=verbose)
            else:
                wordlist_links.seek(0)
                LOGGER.fatal(
                    "There are currently {} wordlist_links available for download, and you "
                    "have chose to download {}. Seeing as there aren't that many right now "
                    "this download will fail, try again with a smaller number..".format(len(wordlist_links.readlines()),
                                                                                        multi)
                )


def random_salt_generator(use_string=False, use_number=False, length=None, warning=True):
    """
      Create a random string of salt to append to the beginning of a hash

      Example:
        >>> random_salt_generator(use_string=True)
        fUFVsatp
    """
    try:
        salt_length = int(length)
    except TypeError:
        salt_length = 8  # default to 8 if length is None
    except ValueError:
        raise ValueError('length must be an integer!')  # default to 8 again???

    char_set = ''
    salt_type = []
    if use_string:
        char_set += string.ascii_letters
        salt_type.append('characters')
    if use_number:
        char_set += string.digits
        salt_type.append('integers')
    if not salt_type:
        # if both `use_string` & `use_number` are False, default to digits
        if warning:
            LOGGER.warning("No choice given as salt, defaulting to numbers..")
        char_set = string.digits
        salt_type.append('integers')

    if salt_length >= 12:
        LOGGER.warning(
            "It is recommended to keep salt length under 12 {} for faster hashing..".format(
                ' and '.join(salt_type)))

    salt = ''.join(random.choice(char_set) for _ in range(salt_length))
    placement = random.choice(("front", "back"))
    return salt, placement


def match_found(data_tuple, data_sep="-" * 75, item_found="+", least_likely="-", kind="cracked", all_types=False):
    """
      Create a banner for finding a match

      > :param data_tuple: tuple containing the information required
      > :param data_sep: what to separate the information with
      > :param item_found: makes it look pretty for the items
      > :param least_likely: makes more pretty formatting for least likely hashes
    """
    if data_tuple is None:
        no_alg_err = (
            "It appears that no algorithm that can match this hash has "
            "been implemented yet. If you feel that this is wrong, "
            "please make a issue regarding this, and we'll see if we "
            "can get it implemented.")
        LOGGER.fatal(no_alg_err)
        shutdown(1)
    if data_tuple[0][1] is None and all_types:
        LOGGER.warning("Only one possible type found for given hash..")
    sort_cracked = ["Clear Text: ", "Hash: ", "Tries attempted: ", "Algorithm Used: "]
    if kind == "cracked":
        print(data_sep + "\n" + "[{}] Match found:\n".format(item_found) + data_sep)
        for i, item in enumerate(sort_cracked):
            print("[{}] {}{}".format(item_found, item, data_tuple[i].upper() if i == 3 else data_tuple[i]))
        print(data_sep)
    else:
        if all_types:
            data_tuple = data_tuple[0] + data_tuple[1]
            print(data_sep + "\n" + "[{}] Most Likely Hash Type(s):\n".format(item_found) + data_sep)
            for i, _ in enumerate(data_tuple):
                if i <= 2:
                    if _ is not None:
                        print("[{}] {}".format(item_found, data_tuple[i].upper()))
                        if i == 2:
                            print(data_sep + "\n" +
                                  "[{}] Least Likely Hash Type(s)(possibly not implemented):\n".format(
                                      least_likely) + data_sep)
                else:
                    if _ is not None:
                        print("[{}] {} {}".format(least_likely, data_tuple[i].upper(), "(not implemented yet)" if _ not in FUNC_DICT.keys() else ""))

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
    if ".git" in os.listdir(os.getcwd()):
        can_update = True
    else:
        can_update = False
    if can_update:
        os.system("git pull origin master")
        return 0
    else:
        return -1




def show_available_algs(show_all=False, supp="+", not_yet="-", spacer1=" "*5, spacer2=" "*3):
    """ Show all algorithms available in the program """
    being_worked_on = [
        "wordpress", "scrypt", "sha2",
        "dsa", "haval160", "tiger160"
    ]
    misc_info_msg = (
        "There are currently {} supported algorithms in Dagon. To "
        "suggest the creation of a new algorithm please go make an "
        "issue here {}")
    LOGGER.info(misc_info_msg.format(len(IDENTIFICATION), DAGON_ISSUE_LINK))
    print("\n{space1}ID#{space2}Alg:\n{space1}---{space2}----".format(space1=spacer1, space2=spacer2))
    for item in sorted(IDENTIFICATION.keys()):
        print("\033[94m[{}]\033[0m  {}{}{}".format(
            supp, item, " " * 3 if len(str(item)) == 3 else " " * 2, IDENTIFICATION[item].upper())
        )
    if show_all:
        print("\nNot implemented yet:")
        for item in sorted(being_worked_on):
            print("\033[91m[{}]\033[0m {}".format(not_yet, item.upper()))


def algorithm_pointers(pointer_identity):
    """ Point to the correct algorithm given by an identification number """
    try:
        return IDENTIFICATION[int(pointer_identity)]
    except TypeError:
        return None
    except (KeyError, ValueError):
        LOGGER.fatal("The algorithm identification number you have specified is invalid.")
        LOGGER.debug("Valid identification numbers are: {}".format(IDENTIFICATION))


def integrity_check(url="https://raw.githubusercontent.com/Ekultek/Dagon/master/md5sum/checksum.md5",
                    path="{}/md5sum/checksum.md5"):
    """ Check the integrity of the program """
    LOGGER.info("Checking program integrity...")
    if open(path.format(os.getcwd())).read() != requests.get(url).text:
        checksum_fail = (
            "MD5 sums did not match from origin master, integrity check"
            " has failed, this could be because there is a new version "
            "available. Please check for a new version and download "
            "that ({}), or be sure that you have not changed any of the"
            " applications code.")
        LOGGER.fatal(checksum_fail.format("https://github.com/ekultek/dagon.git"))
        shutdown(-1)
    return True


def create_dir(dirname, verbose=False):
    """
      Create a directory if it does not exist
      :param dirname: name of the directory
    """
    if not os.path.exists(dirname):
        if verbose:
            LOGGER.debug("Directory '{}/*' not found, creating it..".format(dirname))
        os.mkdir(dirname)
    else:
        if verbose:
            LOGGER.debug("Directory found, skipping..")


def create_file_list(directory=None, cmd_line=None, verbose=False):
    """
      Create a list of files to use either from the terminal line or from a directory

      > :param directory: full path to a directory
      > :param cmd_line: the string given from the command line
      > :param verbose: verbosity run
      > :return: a list

      Example:
        >>> create_file_list(directory=True)
        ['test.txt', 'testing.txt', 'tests.txt']
    """
    if directory is not None:
        if verbose: LOGGER.debug("Searching '{}'..".format(directory))
        file_list = os.listdir(directory)
        if verbose: LOGGER.debug("Found '{}', with a total of {} files..".format(file_list, len(file_list)))
    else:
        file_list = cmd_line.split(",")
        if verbose: LOGGER.debug("Found a total of {} files to use..".format(len(file_list)))
    return file_list


def hash_guarantee(hashed_string):
    """ This will be asked if Dagon fails to find a hash to match yours. """
    question = prompt(
        "Dagon comes with a hash guarantee, if Dagon is unable to crack "
        "your hash successfully, Ekultek will personally attempt to crack "
        "your hash for you. Would you like to automatically create a Github "
        "issue containing your hash", "y/N"
    )
    if question.lower().startswith("y"):
        request_connection(hashed_string)
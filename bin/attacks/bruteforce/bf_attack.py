import itertools
import os

from bin.verify_hashes.verify import verify_hash_type
from lib.settings import FUNC_DICT
from lib.settings import LOGGER
from lib.settings import WORDLIST_RE
from lib.settings import match_found
from lib.settings import prompt
from lib.settings import random_salt_generator

WORDLIST_NAME = "Dagon-bfdict-" + random_salt_generator(use_string=True, length=7)[0] + ".txt"


def word_generator(length_min=7, length_max=15, perms=False):
    """
      Generate the words to be used for bruteforcing
      > :param length_min: minimum length for the word
      > :param length_max: max length for the word
      > :param perms: permutations, True or False
      > :return: a word

      Example:
      >>> word_generator()
      aaaaaa
      aaaaab
      aaaaac
      ...
    """
    chrs = 'abc'
    for n in range(length_min, length_max + 1):
        for xs in itertools.product(chrs, repeat=n):
            if perms is False:
                yield ''.join(xs)
            else:
                LOGGER.fatal("Permutations are not supported yet")
                break


def create_wordlist(max_length=100000, max_word_length=10, warning=True):
    """
      Create a bruteforcing wordlist

      > :param max_length: max amount of words to have
      > :param max_word_length: how long the words should be
      > :param warning: output the warning message to say that BF'ing sucks
      > :return: a wordlist
    """
    warn_msg = "It is highly advised to use a dictionary attack over bruteforce. "
    warn_msg += "Bruteforce requires extreme amounts of memory to accomplish and "
    warn_msg += "it is possible that it could take a lifetime to successfully crack "
    warn_msg += "your hash."
    if warning is True:
        LOGGER.warning(warn_msg)

    with open(WORDLIST_NAME, "a+") as lib:
        word = word_generator(length_max=max_word_length)
        lib.seek(0, 0)
        line_count = len(lib.readlines())
        try:
            for _ in range(line_count, max_length):
                lib.write(next(word) + "\n")
        except StopIteration:
            # if we run out of mutations we'll retry with a word length
            lib.seek(0, 0)
            err_msg = "Ran out of mutations at {} mutations. You can try upping the max length ".format(len(lib.readlines()))
            err_msg += "or just use what was processed. If you make the choice not to continue "
            err_msg += "the program will add +1 to the max length and try to create the wordlist again.."
            LOGGER.error(err_msg)
            q = prompt("Would you like to continue", "y/N")
            if q .lower().startswith("y"):
                pass
            else:
                lib.truncate(0)
                create_wordlist(max_word_length=max_length + 1, warning=False)
    LOGGER.info("Wordlist generated, words saved to: {}. Please re-run the application, exiting..".format(WORDLIST_NAME))
    exit(0)


def hash_words(verify_hash, wordlist, algorithm, salt=None, placement=None):
    tries = 0
    with open(wordlist) as words:
        for i, word in enumerate(words.readlines(), start=1):
            if salt is not None:
                if placement == "front":
                    hashed = FUNC_DICT[algorithm.lower()](word.strip(), salt=salt, front=True)
                else:
                    hashed = FUNC_DICT[algorithm.lower()](word.strip(), salt=salt, back=True)
            else:
                hashed = FUNC_DICT[algorithm.lower()](word.strip())
            tries += 1

            if hashed == verify_hash:
                return word.strip(), hashed, tries, algorithm


def bruteforce_main(verf_hash, algorithm=None, wordlist=None, salt=None, placement=None, all_algs=False):
    wordlist_created = False
    if wordlist is None:
        for item in os.listdir(os.getcwd()):
            if WORDLIST_RE.match(item):
                wordlist_created = True
                wordlist = item
        if wordlist_created is True:
            pass
        else:
            LOGGER.info("Creating wordlist..")
            create_wordlist()
    else:
        LOGGER.info("Reading from, {}..".format(wordlist))

    if algorithm is None:
        hash_type = verify_hash_type(verf_hash, least_likely=all_algs)
        LOGGER.info("Found {} possible hash types to run against {} ".format(len(hash_type),
                                                                             hash_type))
        for alg in hash_type:
            LOGGER.info("Starting bruteforce with {}..".format(alg.upper()))
            bruteforcing = hash_words(verf_hash, wordlist, alg, salt=salt, placement=placement)
            if bruteforcing is None:
                LOGGER.warning("Unable to find a match for '{}', using {}..".format(verf_hash, alg.upper()))
            else:
                match_found(bruteforcing)
                break
    else:
        LOGGER.info("Using algorithm, {}..".format(algorithm.upper()))
        results = hash_words(verf_hash, wordlist, algorithm, salt=salt, placement=placement)
        if results is None:
            LOGGER.warning("Unable to find a match using {}..".format(algorithm.upper()))
            verifiy = prompt("Would you like to attempt to verify the hash type automatically and crack it", "y/N")
            if verifiy.lower().startswith("y"):
                bruteforce_main(verf_hash, wordlist=wordlist, salt=salt, placement=placement)
            else:
                LOGGER.warning("Unable to produce a result for given hash '{}' using {}.. Exiting..".format(
                    verf_hash, algorithm.upper()))
        else:
            match_found(results)


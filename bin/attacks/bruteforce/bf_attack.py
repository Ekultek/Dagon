from __future__ import print_function

import os

from bin.verify_hashes.verify import verify_hash_type
from bin.generators import Generators
from lib.settings import (
    DAGON_ISSUE_LINK,
    FUNC_DICT,
    LOGGER,
    WORDLIST_RE,
    match_found,
    prompt,
    random_salt_generator,
    shutdown,
    create_dir
)

# The name of the wordlist
WORDLIST_NAME = "Dagon-bfdict-" + random_salt_generator(use_string=True, length=7)[0] + ".txt"


def create_wordlist(warning=True, verbose=False, add=False):
    """
      Create a bruteforcing wordlist

      > :param max_length: max amount of words to have
      > :param max_word_length: how long the words should be
      > :param warning: output the warning message to say that BF'ing sucks
      > :return: a wordlist
    """
    max_length, max_word_length, dirname = 10000000, 10, "bf-dicts"
    if add:
        max_word_length += 2

    warn_msg = (
        "It is highly advised to use a dictionary attack over bruteforce. "
        "Bruteforce requires extreme amounts of memory to accomplish and "
        "it is possible that it could take a lifetime to successfully "
        "crack your hash. To run a dictionary attack all you need to do is"
        " pass the wordlist switch ('--wordlist PATH') with the path to "
        "your wordlist. (IE: --bruteforce --wordlist ~/dicts/dict.txt)"
    )

    if warning:
        LOGGER.warning(warn_msg)

    if verbose:
        LOGGER.debug("Creating {} words with a max length of {} characters".format(max_length, max_word_length))

    create_dir(dirname, verbose=verbose)
    with open(dirname + "/" + WORDLIST_NAME, "a+") as lib:
        word = Generators().word_generator(length_max=max_word_length)
        lib.seek(0, 0)
        line_count = len(lib.readlines())
        try:
            for _ in range(line_count, max_length):
                lib.write(next(word) + "\n")
        except StopIteration:  # SHOULD NEVER GET HERE
            # if we run out of mutations we'll retry with a different word length
            lib.seek(0, 0)
            err_msg = (
                "Ran out of mutations at {} mutations. You can try upping "
                "the max length or just use what was processed. If you "
                "make the choice not to continue the program will add +2 "
                "to the max length and try to create the wordlist again.."
            ).format(len(lib.readlines()))
            LOGGER.error(err_msg)
            q = prompt("Would you like to continue", "y/N")
            if not q.startswith(("y", "Y")):
                lib.truncate(0)
                create_wordlist(warning=False, add=True)
    LOGGER.info("Wordlist generated, words saved to: {}. Please re-run the application, exiting..".format(WORDLIST_NAME))
    shutdown()


def hash_words(verify_hash, wordlist, algorithm, salt=None, placement=None, posx="", use_hex=False, verbose=False):
    """
      Hash the words and verify if they match or not

      > :param verify_hash: the has to be verified
      > :param wordlist: the wordlist to be used
      > :param algorithm: the algorithm to be used
      > :param salt: the salt string
      > :param placement: where to place the salt if given
      > :return: the word that matched the hash when hashed, the hash, the amount of tries, and algorithm

    """
    tries = 0
    with open(wordlist) as words:
        for i, word in enumerate(words.readlines(), start=1):
            if salt is not None:
                if placement == "front":
                    hashed = FUNC_DICT[algorithm.lower()](word.strip(), salt=salt, front=True, posx=posx, use_hex=use_hex)
                else:
                    hashed = FUNC_DICT[algorithm.lower()](word.strip(), salt=salt, back=True, posx=posx, use_hex=use_hex)
            else:
                hashed = FUNC_DICT[algorithm.lower()](word.strip(), posx=posx, use_hex=use_hex)
            tries += 1

            if verify_hash == hashed:
                if verbose:
                    LOGGER.debug("Testing against: {}".format(hashed))
                return word.strip(), hashed, tries, algorithm


def bruteforce_main(verf_hash, algorithm=None, wordlist=None, salt=None, placement=None, all_algs=False, posx="",
                    use_hex=False, verbose=False):
    """
      Main function to be used for bruteforcing a hash
    """
    wordlist_created = False
    if wordlist is None:
        for item in os.listdir(os.getcwd() + "/bf-dicts"):
            if WORDLIST_RE.match(item):
                wordlist_created = True
                wordlist = "{}/bf-dicts/{}".format(os.getcwd(), item)
        if not wordlist_created:
            LOGGER.info("Creating wordlist..")
            create_wordlist(verbose=verbose)
    else:
        LOGGER.info("Reading from, {}..".format(wordlist))

    if algorithm is None:
        hash_type = verify_hash_type(verf_hash, least_likely=all_algs)
        LOGGER.info("Found {} possible hash types to run against: {} ".format(len(hash_type) - 1 if hash_type[1] is None
                                                                              else len(hash_type),
                                                                              hash_type[0] if hash_type[1] is None else
                                                                              hash_type))
        for alg in hash_type:
            if alg is None:
                err_msg = (
                    "Ran out of algorithms to try. There are no more "
                    "algorithms currently available that match this hashes"
                    " length, and complexity. Please attempt to use your "
                    "own wordlist (switch '--wordlist'), download one "
                    "(switch '--download'), use salt (switch '-S SALT'), or"
                    " find the algorithm type and create a issue here {}.. ")
                LOGGER.fatal(err_msg.format(DAGON_ISSUE_LINK))
                break
            else:
                if ":::" in verf_hash:
                    LOGGER.debug("It appears that you are trying to crack an '{}' hash, "
                                 "these hashes have a certain sequence to them that looks "
                                 "like this 'USERNAME:SID:LM_HASH:NTLM_HASH:::'. What you're "
                                 "wanting is the NTLM part, of the hash, fix your hash and try "
                                 "again..".format(alg.upper()))
                    shutdown(1)
                LOGGER.info("Starting bruteforce with {}..".format(alg.upper()))
                bruteforcing = hash_words(verf_hash, wordlist, alg, salt=salt, placement=placement, posx=posx,
                                          use_hex=use_hex, verbose=verbose)
                if bruteforcing is None:
                    LOGGER.warning("Unable to find a match for '{}', using {}..".format(verf_hash, alg.upper()))
                else:
                    match_found(bruteforcing)
                    break
    else:
        LOGGER.info("Using algorithm, {}..".format(algorithm.upper()))
        results = hash_words(verf_hash, wordlist, algorithm, salt=salt, placement=placement, posx=posx, verbose=verbose)
        if results is None:
            LOGGER.warning("Unable to find a match using {}..".format(algorithm.upper()))
            verify = prompt("Would you like to attempt to verify the hash type automatically and crack it", "y/N")
            if verify.startswith(("y", "Y")):
                bruteforce_main(verf_hash, wordlist=wordlist, salt=salt, placement=placement, posx=posx, use_hex=use_hex,
                                verbose=verbose)
            else:
                LOGGER.warning("Unable to produce a result for given hash '{}' using {}.. Exiting..".format(
                    verf_hash, algorithm.upper()))
        else:
            match_found(results)

import itertools

import lib


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
    if not perms:
        chrs = 'abc'
        for n in range(length_min, length_max + 1):
            for xs in itertools.product(chrs, repeat=n):
                yield ''.join(xs)
    else:
        raise NotImplementedError("Permutations are not implemented yet.")


def generate_combos(words, verbose=False, **kwargs):
    """
      Create combinations of given words

      > :param words: list of given words
      > :param wordlist_name: name of the file to be created
      > :return: a file containing combinations of different words

      Example:
        >>> generate_combos(["test", "testing", "tests", "spam"])
        testtesting
        testingtests
        testsspam
    """
    wordlist_name = "combos-{}.txt".format(lib.settings.random_salt_generator(use_string=True)[0])
    if verbose:
        lib.settings.LOGGER.debug("Checking if the directory exists..")
    lib.settings.create_dir("combo-dicts", verbose=verbose)
    with open("combo-dicts/{}".format(wordlist_name), "a+") as combodict:
        for i, word in enumerate(words):
            try:
                combodict.write("{}{}\n".format(word.strip(), words[i + 1].strip()))
            except IndexError:
                pass
    lib.settings.LOGGER.info("Wordlist generated and saved under combo-dicts/{}...".format(wordlist_name))


'''def generate_rainbow_tables(words, verbose=False, **kwargs):
    lib.settings.LOGGER.warning(
        "Rainbow table generation is not a fast process, "
        "please be patient while the tables are generated, "
        "this may take a few minutes.."
    )
    if verbose:
        lib.settings.LOGGER.debug("Checking if the directory exists..")
    lib.settings.create_dir("rainbow-tables", verbose=verbose)
    tablename = "rainbow-{}.rtc".format(lib.settings.random_salt_generator(use_string=True)[0])
    with open("rainbow-tables/{}".format(tablename), "a+") as rain:
        for word in words:
            for alg in lib.settings.FUNC_DICT.items():
                rain.write("{};{};{}\n".format(word.strip(), alg[0], lib.settings.FUNC_DICT[alg[0]](word.strip())))
    lib.settings.LOGGER.info("Rainbow table generated and saved under rainbow-tables/{}..".format(tablename))'''

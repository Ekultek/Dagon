import string
import itertools

import bin


class Generators(object):

    CHARS = string.ascii_letters

    def __init__(self, wordlist=None):
        self.words = wordlist

    def word_generator(self, length_min=5, length_max=8):
        """
            Generate the words to be used for bruteforcing

            > :param length_min: minimum length for the word
            > :param length_max: max length for the word
            > :return: a word

            Example:
              >>> Generators().word_generator()
              aaaaa
              aaaab
              aaaac
              ...
              AAAaA
              AAAaB
        """
        for n in range(length_min, length_max + 1):
            for xs in itertools.product(self.CHARS, repeat=n):
                yield ''.join(xs)

    def hash_file_generator(self):
        """
          Parse a given file for anything that matches the hashes in the
          hash type regex dict. Possible that this will pull random bytes
          of data from the files.
        """
        matched_hashes = set()
        keys = [k for k in bin.verify_hashes.verify.HASH_TYPE_REGEX.iterkeys()]
        with open(self.words) as wordlist:
            for item in wordlist.readlines():
                for s in item.split(" "):
                    for k in keys:
                        if k.match(s):
                            matched_hashes.add(s)
            return list(matched_hashes)

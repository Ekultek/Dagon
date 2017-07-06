import string
import itertools


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

    '''def combo_generator(self):
        """
          Generate combos of a wordlist to be used for bruteforcing
        """
        for pair in itertools.permutations(self.words, 2):
            yield ''.join(pair)'''

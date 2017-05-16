from lib.algorithms import *
from bin.verify_hashes import verify
from lib.settings import random_salt_generator, match_found


class DictAttack(object):

    hashed = {}

    def __init__(self, verf_hash, wordlist, salt=None, placement=None,
                 algorithm=None, least=False):
        self.hash = verf_hash
        self.wordlist = wordlist
        self.salt = salt
        self.placement = placement
        self.algorithm = algorithm
        self.least_likely = least

    def get_hash_type(self):
        return verify.verify_hash_type(self.hash, least_likely=self.least_likely)

    def hash_dict(self):
        with open(self.wordlist) as words:
            for word in words.readlines():
                pass

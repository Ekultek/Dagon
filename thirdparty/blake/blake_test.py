#!/usr/bin/env python


intro = """
    blake_test.py
    version 4

    This program tests blake.py individually and against a C
    reference implementation wrapped with blake_wrapper.py.
    It works for both Python2 and Python3.

      Copyright (c) 2009-2012 by Larry Bugbee, Kent, WA
      ALL RIGHTS RESERVED.

      blake_test.py IS EXPERIMENTAL SOFTWARE FOR EDUCATIONAL
      PURPOSES ONLY.  IT IS MADE AVAILABLE "AS-IS" WITHOUT
      WARRANTY OR GUARANTEE OF ANY KIND.  ITS USE SIGNIFIES
      FULL ACCEPTANCE OF ALL RISK, UNDER ALL CIRCUMSTANCES, NO
      EXCEPTIONS.

    To make your learning and experimentation less cumbersome,
    blake_test.py is free for any use.


    Enjoy,

    Larry Bugbee
    April 2012

"""

import sys
from ctypes import *
from binascii import hexlify, unhexlify

_version = '1'

# import two modules with identical class and method names, but
# keep them individually identifiable
have_blake = False
have_blake_wrapper = False

try:
    from blake import BLAKE as BLAKEpy

    have_blake = True
except:
    print('\n   *** unable to import blake.py *** \n')

try:
    from blake_wrapper import BLAKE as BLAKEwrap
    # the next line is obsolesent and will be removed someday
    from blake_wrapper import BLAKE_func as BLAKEwrap_func

    have_blake_wrapper = True
except:
    print('\n   *** unable to import blake_wrapper.py *** \n')


# ---------------------------------------------------------------
# test vectors

def basic_tests():
    if 0:
        print(intro)

    def test_BLAKE(hashlen, msg, expect):
        print('      BLAKE-%d:  msg = %s  length = %d' %
              (hashlen, msg.decode(), len(msg)))
        digest = BLAKE(hashlen).digest(msg)
        print('        %s %s' % ('valid    ' if digest == unhexlify(expect)
                                 else 'ERROR >>>', hexlify(digest).decode()))

    if 1:
        print('')
        print('    single null-byte message:')
        msg = b'\x00'

        hashlen = 256
        expect = (b'0ce8d4ef4dd7cd8d62dfded9d4edb0a7' +
                  b'74ae6a41929a74da23109e8f11139c87')
        test_BLAKE(hashlen, msg, expect)

        hashlen = 224
        expect = (b'4504cb0314fb2a4f7a692e696e487912' +
                  b'fe3f2468fe312c73a5278ec5')
        test_BLAKE(hashlen, msg, expect)

        hashlen = 512
        expect = (b'97961587f6d970faba6d2478045de6d1' +
                  b'fabd09b61ae50932054d52bc29d31be4' +
                  b'ff9102b9f69e2bbdb83be13d4b9c0609' +
                  b'1e5fa0b48bd081b634058be0ec49beb3')
        test_BLAKE(hashlen, msg, expect)

        hashlen = 384
        expect = (b'10281f67e135e90ae8e882251a355510' +
                  b'a719367ad70227b137343e1bc122015c' +
                  b'29391e8545b5272d13a7c2879da3d807')
        test_BLAKE(hashlen, msg, expect)

    if 1:
        print('')
        print('    72 null-bytes message:')
        msg = b'\x00' * 72

        hashlen = 256
        expect = (b'd419bad32d504fb7d44d460c42c5593f' +
                  b'e544fa4c135dec31e21bd9abdcc22d41')
        test_BLAKE(hashlen, msg, expect)

        hashlen = 224
        expect = (b'f5aa00dd1cb847e3140372af7b5c46b4' +
                  b'888d82c8c0a917913cfb5d04')
        test_BLAKE(hashlen, msg, expect)

        print('')
        print('    144 null-bytes message:')
        msg = b'\x00' * 144

        hashlen = 512
        expect = (b'313717d608e9cf758dcb1eb0f0c3cf9f' +
                  b'c150b2d500fb33f51c52afc99d358a2f' +
                  b'1374b8a38bba7974e7f6ef79cab16f22' +
                  b'ce1e649d6e01ad9589c213045d545dde')
        test_BLAKE(hashlen, msg, expect)

        hashlen = 384
        expect = (b'0b9845dd429566cdab772ba195d271ef' +
                  b'fe2d0211f16991d766ba749447c5cde5' +
                  b'69780b2daa66c4b224a2ec2e5d09174c')
        test_BLAKE(hashlen, msg, expect)

    if 1:
        print('')
        print('    more:')

        if 1:
            msg = b'Kilroy was here!'
            hashlen = 256
            expect = (b'b25c02ccfa1f664d25a15d999b56a4be' +
                      b'1ad84a029a96be5d654387a2def99916')
            test_BLAKE(hashlen, msg, expect)

            msg = b'The quick brown fox jumps over the lazy dog'
            hashlen = 512
            expect = (b'1F7E26F63B6AD25A0896FD978FD050A1' +
                      b'766391D2FD0471A77AFB975E5034B7AD' +
                      b'2D9CCF8DFB47ABBBE656E1B82FBC634B' +
                      b'A42CE186E8DC5E1CE09A885D41F43451')
            test_BLAKE(hashlen, msg, expect)

        if 1:
            msg = b'\x00' * 55
            hashlen = 256
            expect = (b'dc980544f4181cc43505318e317cdfd4' +
                      b'334dab81ae035a28818308867ce23060')
            test_BLAKE(hashlen, msg, expect)

            msg = b'\x00' * 56
            hashlen = 256
            expect = (b'26ae7c289ebb79c9f3af2285023ab103' +
                      b'7a9a6db63f0d6b6c6bbd199ab1627508')
            test_BLAKE(hashlen, msg, expect)

            msg = b'\x00' * 111
            hashlen = 512
            expect = (b'125695c5cc01de48d8b107c101778fc4' +
                      b'47a55ad3440a17dc153c6c652faecdbf' +
                      b'017aed68f4f48826b9dfc413ef8f14ae' +
                      b'7dfd8b74a0afcf47b61ce7dcb1058976')
            test_BLAKE(hashlen, msg, expect)

            msg = b'\x00' * 112
            hashlen = 512
            expect = (b'aa42836448c9db34e0e45a49f916b54c' +
                      b'25c9eefe3f9f65db0c13654bcbd9a938' +
                      b'c24251f3bedb7105fa4ea54292ce9ebf' +
                      b'5adea15ce530fb71cdf409387a78c6ff')
            test_BLAKE(hashlen, msg, expect)

    if 0:
        import time
        print('')
        print('    simple timimg test:')

        def time_it(hashsize, iter):
            t0 = time.time()
            for i in range(iter):
                digest = BLAKE(hashsize).digest(b'\x00')  # hash a single null byte
            t1 = time.time()
            template = '    %8d iterations of single-block BLAKE-%d took %8.6f seconds'
            print(template % (iter, hashsize, (t1 - t0)))

        iterations = [10, 100, 1000]
        hashsizes = [256, 512]
        for hashsize in hashsizes:
            for iter in iterations:
                time_it(hashsize, iter)


# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

if have_blake:
    # testing blake.py independently
    BLAKE = BLAKEpy
    print('\n  Testing blake.py:')
    print('  -----------------')
    basic_tests()

if have_blake_wrapper:
    # testing blake_wrapper.py independently
    BLAKE = BLAKEwrap
    BLAKE_func = BLAKEwrap_func
    print('\n  Testing blake_wrapper.py:')
    print('  -------------------------')
    basic_tests()

if have_blake and have_blake_wrapper:
    # now run a series of tests against each other

    print('\n  Comparing results fm blake.py with blake_wrapper.py:')
    print('  ----------------------------------------------------')
    hashsizes = [256, 512]
    testchar = b'\xff'
    for hashsize in hashsizes:
        print('    BLAKE-%d:' % hashsize)
        errors = 0
        for i in range(550):
            if (BLAKEpy(hashsize).final(testchar * i) !=
                    BLAKEwrap(hashsize).final(testchar * i)):
                errors += 1
                print('      *** blake.py and blake_wrapper.py' +
                      ' do not agree for chr(%d)*%d ***' % (testchar, i))
        if not errors:
            print('      no errors found')

print('')


# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
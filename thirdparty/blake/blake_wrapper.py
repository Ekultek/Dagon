
intro = """
    blake_wrapper.py
    version 4

    This is a Python ctypes wrapper for the C reference version
    of BLAKE compiled as a shared library.  It is *MUCH* faster
    than any of the pure Python implementations.

    This wrapper can be used with Python2 and Python3 programs.


    Instructions:
    -------------

    1. Obtain a copy of blake_ref.c and blake_ref.h from

         http://www.131002.net/blake/#dl

    2. Make a trivial mod to blake_ref.h and blake_ref.c:

       To properly support BLAKE's hashState, we need to
       allocate space in the wrapper and pass that state to
       various functions.  The wrapper implements BLAKE as
       a class hiding the passing of the state, nevertheless,
       we need know how much memory to allocate.  ...and to
       do so we need to add a function that returns the size
       of hashState.

       So, to blake_ref.h add:

            /*
              get the hash state size so a wrapper can
              allocate sufficient space for state

              RETURNS
              size of hashState in bytes
            */
            int GetHashStateSize( void );

       And to blake_ref.c add:

            int GetHashStateSize( void ) {
              return sizeof(hashState);
            }

    3. Compile blake_ref.c as a shared library, NOT as a Python
       extension.  I created my libblake.so with the following:

         gcc -O3 -dynamiclib -arch x86_64 -o libblake.so blake_ref.c

       For Linux, change -dynamiclib to -shared.

       Use your favorite tool to create Windows DLLs.  I don't
       have a Windows machine.  When I must I use Digital Mars.
       See:
         http://buggywhip.blogspot.com/2007/07/making-simple-dlls-simply.html

    4. Install the library somewhere on your library search
       list:
            Linux:  LD_LIBRARY_PATH
            Darwin: DYLD_LIBRARY_PATH

    5. Sample usage:

            from blake_wrapper import BLAKE

            blake = BLAKE(256)
            blake.update('Now is the time for all good ')
            blake.update('men to come to the aid of their ')
            digest = blake.final('country.')


    I used blake_ref.c and this wrapper supports that API.  If
    you choose to use another implementation you may need to
    modify this wrapper to support another API.  Those changes
    should be fairly straightforward.


    Legal:
    ------

      Copyright (c) 2009-2012 by Larry Bugbee, Kent, WA
      ALL RIGHTS RESERVED.

      blake_wrapper.py IS EXPERIMENTAL SOFTWARE FOR EDUCATIONAL
      PURPOSES ONLY.  IT IS MADE AVAILABLE "AS-IS" WITHOUT
      WARRANTY OR GUARANTEE OF ANY KIND.  ITS USE SIGNIFIES
      FULL ACCEPTANCE OF ALL RISK, UNDER ALL CIRCUMSTANCES, NO
      EXCEPTIONS.

    To make your learning and experimentation less cumbersome,
    blake_wrapper.py is free for any use.


    Enjoy,

    Larry Bugbee
    March 2011
    May 2011 - fixed Python version check (tx JP)
             - modded to use shared library
    Apr 2012 - obsolesced BLAKE_func() to make APIs the same
               as blake.py



"""


import sys
from ctypes import *

_version = 4

_defaultlibname = 'blake'       # as in libblake.so


# --------------------------------------------------------------------------

class BLAKE(object):
    """ This class supports data in even increments of bytes.
    """

    def __init__(self, hashbitlen):
        """
          load the hashSate structure (copy hashbitlen...)
          hashbitlen: length of the hash output
        """
        if hashbitlen not in [224, 256, 384, 512]:
            raise Exception('hash length not 224, 256, 384 or 512')

        self.hashbitlen = hashbitlen
        self.state = c_buffer(LIB.GetHashStateSize())
        ret = LIB.Init(self.state, hashbitlen)
        if ret:
            raise Exception('Init() ret = %d', ret)
        self.init = 1


    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def addsalt(self, salt):
        """ adds a salt to the hash function (OPTIONAL)
            should be called AFTER Init, and BEFORE update
            salt:  a bytestring, length determined by hashbitlen.
              if hashbitlen=224 or 256, then salt will be 16 bytes
              if hashbitlen=384 or 512, then salt will be 32 bytes
        """
        # fail if addsalt() was not called at the right time
        if self.init != 1:
            raise Exception('addsalt() not called after init() and before update()')

        # is salt size correct?
        saltsize = 16 if self.hashbitlen in [224, 256] else 32
        if len(salt) != saltsize:
            raise Exception('incorrect salt length')

        # do it
        ret = LIB.AddSalt(self.state, salt)
        if ret:
            raise Exception('AddSalt() ret = %d', ret)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def update(self, data):
        """ update the state with new data, storing excess data
            as necessary.  may be called multiple times and if a
            call sends less than a full block in size, the leftover
            is cached and will be consumed in the next call
            data:  data to be hashed (bytestring)
        """
        self.init = 2

        datalen = len(data ) *8
        if not datalen:  return

        ret = LIB.Update(self.state, data, datalen)
        if ret:
            raise Exception('Update() ret = %d', ret)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def final(self, data=b''):
        """ finalize the hash -- pad and hash remaining data
            returns hashval, the digest
        """
        if data:
            self.update(data)

        hashval = c_buffer(int(self. hashbitlen /8))
        ret = LIB.Final(self.state, hashval)
        if ret:
            raise Exception('Final() ret = %d', ret)
        return hashval.raw

    digest = final      # may use .digest() as a synonym for .final()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# BLAKE_func() is obsolescent and is provided here for backward
# compatability.  I will remove this someday.
def BLAKE_func(hashbitlen, data, databitlen):
    """ all-in-one function
        hashbitlen  must be one of 224, 256, 384, 512
        data        data to be hashed (bytestring)
        databitlen  length of data to be hashed in *bits*
        returns     digest value (bytestring)
    """
    return BLAKE(hashbitlen).final(data)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# load the shared library into ctypes

def loadLib(name):
    # prefix might need to change for some platforms       ???
    prefix = ''
    # get the correct library suffix
    libsuffixes = {'darwin': '.so',     # .dylib           ???
                   'linux':  '.so',
                   'linux2': '.so',
                   'win32':  '.dll'}    # .lib             ???
    try:
        libsuffix = libsuffixes[sys.platform]
    except:
        raise Exception('library suffix for "%s" is what?' %
                        sys.platform)
    libname = prefix+ 'lib' + name + libsuffix
    return CDLL(libname)  # load and return the library


LIB = loadLib(_defaultlibname)

LIB.GetHashStateSize.restype = c_int
LIB.Init.restype = c_int
LIB.Update.restype = c_int
LIB.Final.restype = c_int
LIB.GetHashStateSize.argtypes = []
LIB.Init.argtypes = [c_void_p, c_int]
LIB.Update.argtypes = [c_void_p, c_void_p, c_int]
LIB.Final.argtypes = [c_void_p, c_void_p]

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
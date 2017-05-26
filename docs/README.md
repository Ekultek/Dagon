# Dagon - Advanced hash manipulation
#### Named after the prince of Hell, Dagon *(day-gone)* is an advanced hash cracking and manipulation system, capable of bruteforcing multiple hash types, creating bruteforce dictionaries, automatic hashing algorithm verification, random salt generation from Unicode to ASCII, and much more. 

###### Here you will find the complete functionality of Dagon, along with pretty pictures to help you along the way.

![help](https://cloud.githubusercontent.com/assets/14183473/26105976/e1ba4830-3a09-11e7-8bfd-11e1ae056d49.PNG)

# Functionality

Dagon has a lot of options and is capable of cracking almost anything when used properly.

## Mandatory arguments

There are of course mandatory arguments that must be passed so that Dagon can run successfully, in this section I will go over each one of these arguments and tell you a little bit about it, lets begin.

#### _Cracking hashes_:

To crack a hash you must provide a singular hash using the `-c/--crack` flag. This flag will tell Dagon that you are trying to crack a single hash, after you have provided the `-c/--crack` flag you will need to tell Dagon what sort of cracking needs to take place. Here's an example of the cracking flag, for this example we will be using the MD5 hashing algorithm.

Notice that when a wordlist is not provided, Dagon will create its own. This wordlist will contain all possible combinations (up to one million lines) of the letters 'abc' from 7 to 15 characters long

![wordlist_gen](https://cloud.githubusercontent.com/assets/14183473/26103895/359f712c-3a01-11e7-8d36-55a312da0264.PNG)

After the wordlist has been generated, you will be able to crack the password, using that wordlist. Dagon will automatically attempt to verify the algorithm used to create the hash and attempt to crack using the most likely algorithms

![cracking](https://cloud.githubusercontent.com/assets/14183473/26104116/f8538cda-3a01-11e7-87a7-7136042ffc0e.PNG)

#### _Doing a dictionary attack_:

To do a dictionary attack you will just need to use the wordlist flag in order for the bruteforce section to read from the wordlist. 

![wordlist_attack](https://cloud.githubusercontent.com/assets/14183473/26204867/c28c226a-3ba5-11e7-8e0f-4410d1deb3ef.PNG)

#### _Cracking a hash list_:

To crack a list of hashes (file of hashes) you can use the `-l/--hash-list` flag. You will need to provide a full path to a file so that Dagon can attempt to crack each hash. Lets use a file with three hashes in three different algorithms, SHA1, MD5, and WHIRLPOOL. Notice how it will prompt you if you want to crack the hash or not:

![hash_list](https://cloud.githubusercontent.com/assets/14183473/26104288/c9adf220-3a02-11e7-8879-88a6f2a76a42.PNG)

#### _Verify a hashing algorithm_:

You ever have to crack a hash, and the next thing you know you needed to know the hashing algorithm that was used in order to finish the cracking? Well look no further! I have a fix for that as well, using the `-v/--verify` flag! Dagon will not only automatically attempt to verify a hash before cracking, but it can also be provided a hash in order to verify what algorithm was used to create it.

![verify_hash](https://cloud.githubusercontent.com/assets/14183473/26104876/5c9cad90-3a05-11e7-9055-ef6f2c2ad57c.PNG)

You can also pass the `-L/--least-likely` flag and see all possible algorithms that could have been used to create this hash, everything from most likely, to least likely.

![verify_all](https://cloud.githubusercontent.com/assets/14183473/26104919/860ff9de-3a05-11e7-9ad4-69b43981609a.PNG)

### Manipulation arguments

These arguments are given to manipulate the way the application runs, or to manipulate the givens hashes.

#### _Salt manipulation options_:

There are many ways to manipulate the salt in Dagon, anything from using random Unicode salt `--urandom`, random integers `-R`, random characters `-R --use-chars`, random characters & integers `-R --use-chars --use-int`, or creating your own `-S\--salt <SALT>, <PLACEMENT>`. You can also change the length of the salt using the `--salt-size` flag. Most salts are around 10-12 characters long. So making the salt any bigger will produce a warning letting you know:

For random unicode salts, you will need to provide the length of the salt, please keep in mind that Unicode can make the hashing process slower.

![unicode_salt](https://cloud.githubusercontent.com/assets/14183473/26105454/a32957de-3a07-11e7-93c6-2b728d5b7c20.PNG)

Default for random salt is integers

![random_salt](https://cloud.githubusercontent.com/assets/14183473/26105456/a32a3654-3a07-11e7-93d4-3d7d875f3b52.PNG)

Of course you can use just characters if you want to, it's up to you not me

![just_chars](https://cloud.githubusercontent.com/assets/14183473/26105455/a329fe28-3a07-11e7-9e07-79810de38b02.PNG)

But where's the fun in using just characters? You can also use characters and integers

![chars_and_int_salt](https://cloud.githubusercontent.com/assets/14183473/26105457/a32d1e96-3a07-11e7-9c6a-befa73a75778.PNG)

Or, you can always just create your own

![create_your_own](https://cloud.githubusercontent.com/assets/14183473/26105458/a3fb81e6-3a07-11e7-9f03-d357f2c29600.PNG)

You can also change the salt size, because hey, who uses 12 character salts anymore?

![salt_size](https://cloud.githubusercontent.com/assets/14183473/26105647/5dad0be6-3a08-11e7-8757-bb6bc9e375c2.PNG)

### Algorithms available and ID numbers

#### Algorithms currently available

 - MD2        > 120
 - MD4        > 130
 - MD5        > 100
 - Blake224   > 200
 - Blake256   > 210
 - Blake384   > 220 
 - Blake512   > 230
 - SHA1       > 300
 - SHA224     > 310
 - SHA256     > 320
 - SHA384     > 330
 - SHA512     > 340
 - SHA3 224   > 400
 - SHA3 256   > 410
 - SHA3 384   > 420
 - SHA3 512   > 430
 - Ripemd-160 > 600
 - Tiger192   > 700
 - Whirlpool  > 800
 - Blowfish   > 500
 - MySQL      > 510
 - CRC32      > 900
 
#### Special algorithms currently available

 - MD5(MD5(pass)+MD5(salt))> 130
 - MD5(MD5(pass))          > 131
 - Half MD5                > 132
 - MD5(salt+pass+salt)     > 133
 - HALF SHA1               > 351
 - SHA1(SHA1(pass))        > 352

#### Algorithms in the process of being created

 - DSA
 - Oracle
 - Scrypt
 - SHA2
 - Wordpress
 
## Shout out to contributors

 - 4w4k3 (Alisson Moretto)
     The creator of Insanity Framework. Thank you for being an all around badass. When you get a chance go check out the repo's: https://github.com/4w4k3
# Dagon - Advanced Hash Manipulation
#### Named after the prince of Hell, Dagon *(day-gone)* is an advanced hash cracking and manipulation system, capable of bruteforcing multiple hash types, creating bruteforce dictionaries, automatic hashing algorithm verification, random salt generation from Unicode to ASCII, and much more. 
_Note: I personally guarantee Dagon will crack your hash, if for any reason Dagon is incapable or fails, create an issue with your hash and I will create a patch for the hash and attempt to crack your hash for you._

# Screenshots

Bruteforcing made easy with a built in wordlist creator if you do not specify one. The wordlist will create 100,000 strings to use
![bruteforce](https://cloud.githubusercontent.com/assets/14183473/26070657/fc6ef54e-396a-11e7-8479-5410ea2d170d.PNG)

Verify what algorithm was used to create that hash you're trying to crack. You can specify to view all possible algorithms by providing the -L flag (some algorithms are not implemented yet)
![hash_verification](https://cloud.githubusercontent.com/assets/14183473/26070690/1cd632a2-396b-11e7-89cc-20182d347848.PNG)

Random salting, unicode random salting, or you can make your own choice on the salt.
![salting](https://cloud.githubusercontent.com/assets/14183473/26070692/1eb062f0-396b-11e7-91bb-4238bd241bef.PNG)

# Demo video

[![demo](https://cloud.githubusercontent.com/assets/14183473/26458859/27a9b61e-413a-11e7-8bd4-0583eae12ddd.PNG)](https://vimeo.com/218966256)

# Download

Preferable you can close the repository with `git clone https://github.com/ekultek/dagon.git` alternatively you can download the zip or tarball [here](https://github.com/ekultek/dagon/releases)

# Basic usage

For full functionality of Dagon please reference the homepage [here](https://ekultek.github.io/Dagon/) or the [user manual](https://github.com/Ekultek/Dagon/wiki)

`python dagon.py -h` This will run the help menu and provide a list of all possible flags

`python dagon.py -c <HASH> --bruteforce` This will attempt to bruteforce a given hash

`python dagon.py -l <FILE-PATH> --bruteforce` This will attempt to bruteforce a given file full of hashes (one per line)

`python dagon.py -v <HASH>` This will try to verify the algorithm used to create the hash

`python dagon.py -V <FILE-PATH>` This will attempt to verify each hash in a file, one per line

# Installation

Dagon requires python version `2.7.x` to run successfully.

 - `git clone https://github.com/ekultek/dagon.git`
 - `cd Dagon`
 - `pip install -r requirements.txt`
 
This should install all the dependencies that you will need to run Dagon

# Contributions

All contributions are greatly appreciated and helpful. When you contribute you will get your name placed on the homepage underneath contributions with a link to your contribution. You will also get massive respect from me, and that's a pretty cool thing. What I'm looking for in contributions is some of the following:

 - Hashing algorithm creations, specifically; A quicker MD2 algorithm, full Tiger algorithms, Keychain algorithms for cloud and agile
 - More wordlists to download from, please make sure that the link is encoded
 - Rainbow table attack implementation
 - More regular expressions to verify different hash types
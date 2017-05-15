# Dagon
#### Named after the prince of Hell, Dagon *(day-gone)* is a advanced hash cracking and manipulation system, capable of bruteforcing multiple hash types, creating bruteforce dictionaries, automatic hashing algorithm verification, random salt generation from unicode to ascii, and much more.

# Screenshots

Bruteforcing made easy with a built in wordlist creator if you do not specify one. The wordlist will create 100,000 strings to use
![bruteforce](https://cloud.githubusercontent.com/assets/14183473/26070657/fc6ef54e-396a-11e7-8479-5410ea2d170d.PNG)

Verify what algorithm was used to create that hash you're trying to crack. You can specify to view all possible algorithms by providing the -L flag (some algorithms are not implemented yet)
![hash_verification](https://cloud.githubusercontent.com/assets/14183473/26070690/1cd632a2-396b-11e7-89cc-20182d347848.PNG)

Random salting, unicode random salting, or you can make your own choice on the salt.
![salting](https://cloud.githubusercontent.com/assets/14183473/26070692/1eb062f0-396b-11e7-91bb-4238bd241bef.PNG)

# Download

Preferable you can close the repository with `git clone https://github.com/ekultek/dagon.git` alternativley you can download the zip or tarball [here](https://github.com/ekultek/dagon/releases)

# Basic usage

`python dagon.py -h` This will run the help menu and provide a list of all possible flags

`python dagon.py -c <HASH> --bruteforce` This will attempt to bruteforce a given hash

`python dagon.py -l <FILE-PATH> --bruteforce` This will attempt to bruteforce a given file full of hashes (one per line)

`python dagon.py -v <HASH>` This will try to verify the algorithm used to create the hash

# Installation

 - `git clone https://github.com/ekultek/dagon.git`
 - `cd Dagon`
 - `pip install -r requirements.txt`
 
This should install all the dependencies that you will need to run Dagon

# Contributions

Of course all contributions are not only welcome, they are needed! This project needs your help to become better! See something wrong? Find an algorithm that you want implemented? Find a bug, or an issue? Well make an issue or a pull request and lets get that problem sorted! Together we can accomplish anything.
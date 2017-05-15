import optparse
import os
import random
import subprocess
import sys
import time
from bin.attacks.bruteforce.bf_attack import bruteforce_main
from bin.verify_hashes.verify import verify_hash_type
from lib.settings import LOGGER, prompt, match_found
from lib.settings import show_banner, show_hidden_banner, random_salt_generator

if __name__ == '__main__':

    parser = optparse.OptionParser(usage="dagon [c|l] HASH|HASH-LIST")

    # Mandatory arguments, required for program to run
    mandatory = optparse.OptionGroup(parser, "Mandatory arguments",
                                     description="These arguments are mandatory to run the application")
    mandatory.add_option("-c", "--crack", dest="hashToCrack", metavar="HASH",
                         help="Specify a hash to crack")
    mandatory.add_option("-l", "--hash-list", dest="hashListToCrack", metavar="FILE-PATH",
                         help="Provide a file of hashes to crack")
    mandatory.add_option("-v", "--verify", dest="verifyHashType", metavar="HASH",
                         help="Attempt to find the type of algorithm used given a specified hash.")

    # Specific arguments, what do you want the program to do?
    specifics = optparse.OptionGroup(parser, "Specifics on what is to be done arguments",
                                     description="These arguments tell the program what to do")
    specifics.add_option("-b", "--bruteforce", action="store_true", dest="bruteforceCrack",
                         help="Attempt to bruteforce a given hash")
    specifics.add_option("-d", "--dict-attack", dest="dickAttackCrack", metavar="FILE-PATH",
                         help=optparse.SUPPRESS_HELP)
    specifics.add_option("-r", "--rainbow", dest="rainbowTableAttack", metavar="FILE-PATH",
                         help=optparse.SUPPRESS_HELP)

    # Manipulation arguments to manipulate the hashes into what you want them to be
    manipulation = optparse.OptionGroup(parser, "Manipulation arguments",
                                        description="These arguments can manipulate the hashes")
    manipulation.add_option("-S", "--salt", dest="saltToUseAndPlacement", nargs=2, metavar="SALT, PLACEMENT",
                            help="Choose your salt and placement to use in the hashing")
    manipulation.add_option("-R", "--rand-salt", dest="randomSaltAndPlacement", action="store_true",
                            help="Random generate the salt and the placement to put the salt in")
    manipulation.add_option("-L", "--least-likely", dest="displayLeastLikely", action="store_true",
                            help="Display the least likely hash types during verification")
    manipulation.add_option("-W", "--wordlist", dest="wordListToUse", metavar="FILE-PATH",
                            help="Specify a wordlist to use for bruteforcing")
    manipulation.add_option("-A", "--algorithm", dest="algToUse", metavar="ALGORITHM",
                            help="Specify what algorithm to use for cracking")
    manipulation.add_option("--use-chars", dest="useCharsAsSalt", action="store_true",
                            help="Use random characters for the salt")
    manipulation.add_option("--use-int", dest="useIntAsSalt", action="store_true",
                            help="Use random integers as the salt, default if no option is given")
    manipulation.add_option("--salt-size", dest="saltSizeToUse", metavar="SALT-LENGTH",
                            help="Choose how long you want your salt to be")
    manipulation.add_option("--urandom", dest="useURandomSaltAndRandomPlacement", metavar="LENGTH",
                            help="Use unicode salt for thehash salting, along with a random placement")

    # Misc arguments that you can give to the program
    misc = optparse.OptionGroup(parser, "Miscellaneous arguments",
                                description="Misc arguments that can be given to help with processing")
    misc.add_option("-B", "--benchmark", dest="runBenchMarkTest", action="store_true",
                    help="Find out how long it took for the application to find the matching hash")
    misc.add_option("-H", "--hide", action="store_true", dest="hideBanner",
                    help="Hide the application banner and show a mini version of it")

    parser.add_option_group(mandatory)
    parser.add_option_group(manipulation)
    parser.add_option_group(specifics)
    parser.add_option_group(misc)

    # Pay no attention to the _ it's required :\
    opt, _ = parser.parse_args()

    required_args = ["-c", "--crack", "-l", "--hash-list", "-v", "--verify"]
    args_in_params = 0

    show_banner() if opt.hideBanner is not True else show_hidden_banner()

    if len(sys.argv) <= 1:
        LOGGER.fatal("You have failed to provide a flag for to the application and have been "
                     "redirected to the help menu.")
        time.sleep(1.7)
        subprocess.call("python dagon.py --help")
    else:
        try:
            # Check that you provided a mandatory argument
            for i, _ in enumerate(sys.argv):
                if sys.argv[i] in required_args:
                    args_in_params += 1
            # If you provided an argument continue..
            if args_in_params > 0:

                # Benchmark testing
                if opt.runBenchMarkTest is True:
                    start_time = time.time()
                    LOGGER.info("Benchmark test start: {}".format(start_time))

                # Creating random salts and random placements
                if opt.randomSaltAndPlacement is True:
                    salt, placement = random_salt_generator(opt.useCharsAsSalt, opt.useIntAsSalt,
                                                            opt.saltSizeToUse)
                    LOGGER.info("Using random salt: '{}' and random placement: '{}'...".format(salt, placement))

                # If you provided your own salt and your own placements
                elif opt.saltToUseAndPlacement is not None:
                    salt, placement = opt.saltToUseAndPlacement[0], opt.saltToUseAndPlacement[1].lower()
                    LOGGER.info("Using salt: '{}' on the {} of the hash...".format(salt, placement))

                # Unicode random salt and placement
                elif opt.useURandomSaltAndRandomPlacement is not None:
                    salt, placement = str(os.urandom(int(opt.useURandomSaltAndRandomPlacement))), random.choice(["front",
                                                                                                                    "back"])
                    LOGGER.info("Using urandom salt: '{}' on the {} of the hash...".format(salt, placement))

                # No salt or placement
                else:
                    salt, placement = None, None

                # Bruteforce this shit
                if opt.bruteforceCrack is True and opt.hashToCrack is not None and opt.hashListToCrack is None:
                    try:
                        bruteforce_main(opt.hashToCrack, algorithm=opt.algToUse, wordlist=opt.wordListToUse,
                                        salt=salt, placement=placement)
                    except Exception as e:
                        LOGGER.fatal("{} failed with error code: '{}'".format(os.path.basename(__file__), e))

                # Bruteforce a list of hashes
                elif opt.bruteforceCrack is True and opt.hashListToCrack is not None and opt.hashToCrack is None:
                    try:
                        with open(opt.hashListToCrack) as hashes:
                            for i, hash_to_crack in enumerate(hashes.readlines(), start=1):
                                crack_or_not = prompt("Attempt to crack: '{}'".format(hash_to_crack.strip()), "y/N")
                                if crack_or_not.lower().startswith("y"):
                                    LOGGER.info("Cracking hash number {}..".format(i))
                                    bruteforce_main(hash_to_crack.strip(), algorithm=opt.algToUse,
                                                    wordlist=opt.wordListToUse, salt=salt,
                                                    placement=placement)

                                    print("\n")
                    except Exception as e:
                        LOGGER.fatal("Failed with error code: {}. Check the file and try again..".format(e))

                # TODO:/ create the dict and rainbow attacks

                # Verify a given hash to see what type of algorithm might have been used
                elif opt.verifyHashType is not None:
                    LOGGER.info("Analyzing given hash: '{}'...".format(opt.verifyHashType))
                    match_found(verify_hash_type(opt.verifyHashType, least_likely=opt.displayLeastLikely), kind="else",
                                all_types=opt.displayLeastLikely)

                # Finish the benchmark test
                if opt.runBenchMarkTest is True:
                    stop_time = time.time()
                    LOGGER.info("Benchmark test finish: {}".format(stop_time))
                    LOGGER.info("Time elapsed: {} seconds".format(stop_time - start_time))

            # You never provided a mandatory argument
            else:
                LOGGER.fatal("Missing mandatory argument, redirecting to help menu..")
                subprocess.call("python dagon.py --help")

        # Why you gotta interrupt my awesome?
        except KeyboardInterrupt:
            LOGGER.fatal("User aborted sequence..")

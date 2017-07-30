#! usr/bin/env python

import optparse
import os
import random
import subprocess
import sys
import time

from bin.verify_hashes.verify import verify_hash_type
from bin.generators import Generators
from bin.attacks.bruteforce.bf_attack import (
    bruteforce_main,
    create_wordlist
)
from lib.settings import (
    CLONE,
    LOGGER,
    VERSION_STRING,
    algorithm_pointers,
    download_rand_wordlist,
    integrity_check,
    match_found,
    prompt,
    random_salt_generator,
    show_available_algs,
    show_banner,
    show_hidden_banner,
    start_up, shutdown,
    update_system,
    verify_python_version,
    create_dir
)

if __name__ == '__main__':

    parser = optparse.OptionParser(usage="dagon [c|v|V|l] HASH|HASH-LIST --bruteforce [OPTS]")

    # Mandatory arguments, required for program to run
    mandatory = optparse.OptionGroup(parser, "Mandatory arguments",
                                     description="These arguments are mandatory to run the application")
    mandatory.add_option("-c", "--crack", dest="hashToCrack", metavar="HASH",
                         help="Specify a hash to crack")
    mandatory.add_option("-l", "--hash-list", dest="hashListToCrack", metavar="FILE-PATH",
                         help="Provide a file of hashes to crack")
    mandatory.add_option("-v", "--verify", dest="verifyHashType", metavar="HASH",
                         help="Attempt to find the type of algorithm used given a specified hash.")
    mandatory.add_option("-V", "--verify-list", dest="verifyHashList", metavar="PATH",
                         help="Run through a file containing hashes (one per line) and attempt to verify them")

    # Specific arguments, what do you want the program to do?
    tech = optparse.OptionGroup(parser, "Technique arguments",
                                description="These arguments tell the program what to do technique wise.")
    tech.add_option("-b", "--bruteforce", action="store_true", dest="bruteforceCrack",
                    help="Attempt to bruteforce a given hash")
    tech.add_option("-r", "--rainbow", dest="rainbowTableAttack", metavar="FILE-PATH",
                    help=optparse.SUPPRESS_HELP)  # Not implemented yet

    # Manipulation arguments to manipulate the hashes into what you want them to be
    manipulation = optparse.OptionGroup(parser, "Manipulation arguments",
                                        description="These arguments can manipulate the hashes")
    manipulation.add_option("-S", "--salt", dest="saltToUseAndPlacement", nargs=2, metavar="SALT, PLACEMENT",
                            help="Choose your salt and placement to use in the hashing")
    manipulation.add_option("-R", "--rand-salt", dest="randomSaltAndPlacement", action="store_true",
                            help="Randomly generate the salt and the placement to put the salt in")
    manipulation.add_option("-A", "--algorithm", dest="algToUse", metavar="ALGORITHM-IDENTIFIER",
                            help="Specify what algorithm to use for cracking")
    manipulation.add_option("--use-chars", dest="useCharsAsSalt", action="store_true",
                            help="Use random characters for the salt")
    manipulation.add_option("--use-int", dest="useIntAsSalt", action="store_true",
                            help="Use random integers as the salt, default if no option is given")
    manipulation.add_option("--salt-size", dest="saltSizeToUse", metavar="SALT-LENGTH",
                            help="Choose how long you want your salt to be")
    manipulation.add_option("--urandom", dest="useURandomSaltAndRandomPlacement", metavar="LENGTH",
                            help="Use random bytes as the salt, randomness is based on your OS.")
    manipulation.add_option("--posx", dest="returnThisPartOfHash", metavar="POSITION",
                            help="Choose which part of the hashes you want to return, "
                                 "only valid for half algorithms functions")
    manipulation.add_option("--use-hex", action="store_true", dest="useHexCodeNotHash",
                            help="Use the CRC32/CRC64 hexcode instead of the hash")

    # Manipulate your dictionary attacks with these options
    dictionary_attack_opts = optparse.OptionGroup(parser, "Dictionary attack arguments",
                                                  description="These are the options available to manipulate your "
                                                              "dict attacks")
    dictionary_attack_opts.add_option("-w", "--wordlist", dest="wordListToUse", metavar="FILE-PATH",
                                      help="Specify a wordlist to do the cracking with")
    dictionary_attack_opts.add_option("--download", dest="downloadWordList", action="store_true",
                                      help="Download a random wordlist")
    dictionary_attack_opts.add_option("--download-x", dest="downloadMultiple", metavar="AMOUNT", type=int,
                                      help="Download multiple wordlists at a time")
    dictionary_attack_opts.add_option("-W", "--multi-wordlist", dest="multiWordLists", metavar="WORDLISTS",
                                      help="Use multiple wordlists at a time to do the cracking seperated by"
                                           " a comma, IE 'test.txt, testing.txt'")

    # Misc arguments that you can give to the program
    misc = optparse.OptionGroup(parser, "Miscellaneous arguments",
                                description="Misc arguments that can be given to help with processing")
    misc.add_option("-L", "--least-likely", dest="displayLeastLikely", action="store_true",
                    help="Display the least likely hash types during verification")
    misc.add_option("-B", "--benchmark", dest="runBenchMarkTest", action="store_true",
                    help="Find out how long it took to finish the process by timing the application")
    misc.add_option("-H", "--hash-file", dest="createHashFile", metavar="FILENAME",
                    help='Parse a singular file or a series of files separated by commas for hashes. '
                         'IE -F "test.txt, testing.txt" or -F test.txt')
    misc.add_option("-I", "--integrity-check", action="store_true", dest="testProgramIntegrity",
                    help="Run an integrity check on the program, this can be used to check for updates,"
                         "check if the program md5sums match, or just to check your internet connection")
    misc.add_option("--banner", action="store_true", dest="hideBanner",
                    help="Display the full Dagon banner")
    misc.add_option("--update", dest="updateDagon", action="store_true",
                    help="Update the program to the latest development version")
    misc.add_option("--avail-algs", action="store_true", dest="showAvailableAlgorithms",
                    help="Show all available algorithms that are currently functional.")
    misc.add_option("--all-algs", action="store_true", dest="showAllAlgorithms",
                    help="Use in conjunction with --avail-algs to show future supported algorithms")
    misc.add_option("--version", action="store_true", dest="displayVersionInfo",
                    help="Display the version information and exit.")
    misc.add_option("--batch", action="store_true", dest="runInBatchMode",
                    help="Run in batch and skip the questions")
    misc.add_option("--verbose", action="store_true", dest="runInVerbose",
                    help="Run the application verbosely")

    parser.add_option_group(mandatory)
    parser.add_option_group(manipulation)
    parser.add_option_group(dictionary_attack_opts)
    parser.add_option_group(tech)
    parser.add_option_group(misc)

    # Pay no attention to the _ it's required..
    opt, _ = parser.parse_args()

    verify_python_version(verbose=opt.runInVerbose)  # need this again :|

    required_args = ["-c", "--crack",
                     "-l", "--hash-list",
                     "-v", "--verify",
                     "-V", "--verify-list"]
    args_in_params = 0

    show_banner() if opt.hideBanner else show_hidden_banner()

    if len(sys.argv) <= 1:
        LOGGER.fatal("You have failed to provide a flag to the application and have been redirected to the help menu.")
        time.sleep(1.7)
        subprocess.call("python dagon.py --help", shell=True)
    else:
        try:
            if opt.testProgramIntegrity:
                status = integrity_check()
                if status:
                    LOGGER.info(
                        "Integrity check has passed successfully, there are no updates "
                        "available at the moment and you are running the latest version."
                    )
                    exit(0)

            # Download a random wordlist
            if opt.downloadWordList or opt.downloadMultiple:
                download_rand_wordlist(verbose=opt.runInVerbose,
                                       multi=opt.downloadMultiple if opt.downloadMultiple is not None else 1)
                exit(0)

            # Output all supported algorithms
            if opt.showAvailableAlgorithms:
                show_available_algs(show_all=opt.showAllAlgorithms)
                exit(0)

            # Display the version and exit
            if opt.displayVersionInfo:
                LOGGER.info(VERSION_STRING)
                exit(0)

            # Update Dagon
            if opt.updateDagon:
                LOGGER.info("Update in progress..")
                update_status = update_system()
                if update_status == 1:
                    LOGGER.info("Dagon is already equal with origin master.")
                elif update_status == -1:
                    LOGGER.error(
                        "Dagon experienced an error while updating, please download manually from: {}".format(CLONE))
                else:
                    LOGGER.info("Dagon has successfully updated to the latest version.")
                exit(0)

            # create a hash list from a given file or a series of given files
            # for this to work effectively when passing multiple files you must
            # enclose them in quotes and separate them by commas, IE -H "test.txt, testing.txt".
            # This will parse the given file for anything pertaining to a hash and save it
            # under a new file. You can then pass that file to the program
            if opt.createHashFile:
                files_to_process = opt.createHashFile
                hash_file_name = "hash-file-{}.hash".format(random_salt_generator(use_string=True)[0])
                create_dir("{}/hash_files".format(os.getcwd()), verbose=opt.runInVerbose)
                full_hash_path = "{}/{}/{}".format(os.getcwd(), "hash_files", hash_file_name)
                with open(full_hash_path, "a+") as filename:
                    if len(files_to_process.split(",")) > 1:
                        LOGGER.info("Found multiple files to process: '{}'..".format(files_to_process))
                        for f in files_to_process.split(","):
                            try:
                                for item in Generators(f.strip()).hash_file_generator():
                                    filename.write(item.strip() + "\n")
                            except IOError:
                                LOGGER.warning("Provided file '{}' does not exist, skipping..".format(f.strip()))
                                continue
                    else:
                        LOGGER.info("Reading from singular file '{}'...".format(files_to_process))
                        for item in Generators(opt.createHashFile).hash_file_generator():
                            filename.write(item.strip() + "\n")

                if not open(full_hash_path).readlines():
                    LOGGER.warning("No processable hashes found in '{}'..".format(files_to_process))
                else:
                    LOGGER.info("Created file '{}' under '{}'..".format(hash_file_name, full_hash_path))
                exit(0)

            # Check that you provided a mandatory argument
            for i, _ in enumerate(sys.argv):
                if sys.argv[i] in required_args:
                    args_in_params += 1

            # If you provided an argument continue..
            if args_in_params > 0:

                start_up(verbose=opt.runInVerbose)

                # Show the options being used at the time of the run if verbose is True
                if opt.runInVerbose:
                    opts_being_used = []
                    for o, v in opt.__dict__.items():
                        if v is not None:
                            opts_being_used.append((o, v))
                    LOGGER.debug("Options being used: {}..".format(dict(opts_being_used)))

                # Benchmark testing
                if opt.runBenchMarkTest:
                    start_time = time.time()

                # Creating random salts and random placements
                if opt.randomSaltAndPlacement:
                    salt, placement = random_salt_generator(opt.useCharsAsSalt, opt.useIntAsSalt,
                                                            opt.saltSizeToUse)
                    LOGGER.info("Using random salt: '{}' and random placement: '{}'...".format(salt, placement))

                # If you provided your own salt and your own placements
                elif opt.saltToUseAndPlacement is not None:
                    salt, placement = opt.saltToUseAndPlacement[0], opt.saltToUseAndPlacement[1].lower()
                    LOGGER.info("Using salt: '{}' on the '{}' of the hash...".format(salt, placement))

                # Unicode random salt and placement
                elif opt.useURandomSaltAndRandomPlacement is not None:
                    salt, placement = str(os.urandom(int(opt.useURandomSaltAndRandomPlacement))), random.choice(
                        ["front", "back"])
                    LOGGER.info("Using urandom salt: '{}' on the '{}' of the hash...".format(salt, placement))

                # No salt or placement
                else:
                    salt, placement = None, None

                # Bruteforce this shit
                if opt.bruteforceCrack and opt.hashToCrack is not None and opt.hashListToCrack is None:
                    try:
                        if opt.multiWordLists is not None:
                            for item in opt.multiWordLists.split(","):
                                bruteforce_main(opt.hashToCrack, algorithm=algorithm_pointers(opt.algToUse),
                                                wordlist=item.strip(), salt=salt, placement=placement,
                                                posx=opt.returnThisPartOfHash,
                                                use_hex=opt.useHexCodeNotHash, verbose=opt.runInVerbose)
                        else:
                            bruteforce_main(opt.hashToCrack, algorithm=algorithm_pointers(opt.algToUse),
                                            wordlist=opt.wordListToUse,
                                            salt=salt, placement=placement, posx=opt.returnThisPartOfHash,
                                            use_hex=opt.useHexCodeNotHash, verbose=opt.runInVerbose)
                    except Exception as e:
                        LOGGER.fatal("{} failed with error code: '{}'. Creating a wordlist..".format(os.path.basename(__file__), e))
                        create_wordlist(verbose=opt.runInVerbose)

                # Bruteforce a list of hashes
                elif opt.bruteforceCrack and opt.hashListToCrack is not None and opt.hashToCrack is None:
                    try:
                        with open(opt.hashListToCrack) as hashes:
                            for i, hash_to_crack in enumerate(hashes.readlines(), start=1):
                                if opt.runInBatchMode:
                                    crack_or_not = "y"
                                else:
                                    crack_or_not = prompt("Attempt to crack: '{}'".format(hash_to_crack.strip()), "y/N")

                                if crack_or_not.startswith(("y", "Y")):
                                    LOGGER.info("Cracking hash number {}..".format(i))
                                    bruteforce_main(hash_to_crack.strip(), algorithm=algorithm_pointers(opt.algToUse),
                                                    wordlist=opt.wordListToUse, salt=salt,
                                                    placement=placement, posx=opt.returnThisPartOfHash,
                                                    use_hex=opt.useHexCodeNotHash, verbose=opt.runInVerbose)

                                    print("\n")
                    except Exception as e:
                        LOGGER.fatal("Failed with error code: '{}'. Check the file and try again..".format(e))

                # TODO:/ create rainbow attacks

                # Verify a given hash to see what type of algorithm might have been used
                elif opt.verifyHashType is not None:
                    LOGGER.info("Analyzing given hash: '{}'...".format(opt.verifyHashType))
                    match_found(verify_hash_type(opt.verifyHashType, least_likely=opt.displayLeastLikely), kind="else",
                                all_types=opt.displayLeastLikely)

                # Verify a file of hashes, one per line
                elif opt.verifyHashList is not None:
                    with open(opt.verifyHashList) as hashes:
                        hashes.seek(0, 0)
                        total_hashes = hashes.readlines()
                        LOGGER.info("Found a total of {} hashes to verify..".format(len(total_hashes)))
                        for h in total_hashes:
                            print("")
                            LOGGER.info("Analyzing hash: '{}'".format(h.strip()))
                            if opt.runInBatchMode:
                                q = "y"
                            else:
                                q = prompt("Attempt to verify hash '{}'".format(h.strip()), "y/N")

                            if q.startswith(("y", "Y")):
                                match_found(verify_hash_type(h.strip(), least_likely=opt.displayLeastLikely),
                                            kind="else",
                                            all_types=opt.displayLeastLikely)

                # Finish the benchmark test
                if opt.runBenchMarkTest:
                    stop_time = time.time()
                    LOGGER.info("Time elapsed during benchmark test: {} seconds".format(stop_time - start_time))

                shutdown(verbose=opt.runInVerbose)

            # You never provided a mandatory argument
            else:
                LOGGER.fatal("Missing mandatory argument, redirecting to help menu..")
                subprocess.call("python dagon.py --help", shell=True)

        # Why you gotta interrupt my awesome?
        except KeyboardInterrupt:
            LOGGER.fatal("User exited process...")
            # TODO:/ Pause/resume function'''

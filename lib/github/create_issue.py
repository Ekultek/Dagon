import os
import sys
import json
import urllib
import datetime
import urllib2
import string
import random
import platform

import lib


def __handle(encoded):
    data_specs = [
        (0, 10), (10, 30), (30, 40), (40, 60), (60, -1)
    ]

    def __find_n(token, retval="1"):
        return retval + token[-1]

    def __decode(string, n):
        for _ in range(int(n) + 1):
            string = string.decode("base64")
        return string

    n = __find_n(encoded)
    decoded = __decode(encoded, n)
    data_list = [
        decoded[data_specs[0][0]:data_specs[0][1]],
        decoded[data_specs[1][0]:data_specs[1][1]],
        decoded[data_specs[2][0]:data_specs[2][1]],
        decoded[data_specs[3][0]:data_specs[3][1]],
        decoded[data_specs[4][0]:data_specs[4][1]]
    ]
    token = data_list[1] + data_list[3]
    return token


def __get_encoded_string(path="{}/lib/github/auth/oauth"):
    with open(path.format(os.getcwd())) as data:
        return data.read().strip()


def __find_algorithm_used(cmd_line=sys.argv, alg_cmd="-A"):
    if alg_cmd in cmd_line:
        for i, item in enumerate(cmd_line):
            if item == alg_cmd:
                return lib.settings.IDENTIFICATION[int(cmd_line[i + 1])].upper()
    else:
        return None


def request_connection(hashed_string, date_created=datetime.datetime.today()):

    lib.settings.LOGGER.warning("automatic issue creation has been turned off for the time being.")
    '''def __create_title(s):
        return s[:9]

    issue_title = "Hash guarantee ({})".format(__create_title(hashed_string))

    issue_data = {
        "title": issue_title,
        "body": open("{}/lib/github/template".format(os.getcwd())).read().format(
            hashed_string, date_created, sys.argv, __find_algorithm_used()
        ),
        "labels": ["hash guarantee", "algorithm issue"]
    }

    req = urllib2.Request(
        url="https://api.github.com/repos/ekultek/Dagon/issues", data=json.dumps(issue_data),
        headers={"Authorization": "token {}".format(__handle(__get_encoded_string()))})

    urllib2.urlopen(req).read()
    lib.settings.LOGGER.info(
        "Your issue has been created with the title '{}'. If you so wish "
        "you can provide more information about where you got this hash, by "
        "sending an email to: {}.\nDoing so will help with the cracking "
        "of your hash, and can make the cracking aspect go by faster.\n"
        "Information that will need to be provided will be basic, just "
        "where you got the hash (database, application, etc), and the "
        "type of database, application, etc, that it was gained from.\n"
        "If you choose not to provide the information, please allow up-to "
        "7 days for an attempt at cracking your hash, along with the patch "
        "for your hash to be pushed through.".format(
            issue_title, lib.settings.DAGON_EMAIL
        )
    )


def dagon_failure(issue, hashed_string, error):

    def __create_issue_ext():
        retval = []
        for _ in range(5):
            retval.append(random.choice(string.ascii_letters))
        return ''.join(retval)

    issue_title = "Unhandled Exception {}({})".format(issue, __create_issue_ext())
    issue_data = {
        "title": issue_title,
        "body": open("{}/lib/github/issue_template".format(os.getcwd())).read().format(
            type(error).__name__, (error.args, error.message), platform.platform(),
            hashed_string, sys.argv
        )
    }
    encoded_issue_data = urllib.urlencode(issue_data)
    req = urllib2.Request(
        url="https://api.github.com/repos/ekultek/Dagon/issues", data=json.dumps(json.dumps(encoded_issue_data)),
        headers={"Authorization": "token {}".format(__handle(__get_encoded_string()))})

    urllib2.urlopen(req).read()
    lib.settings.LOGGER.info(
        "Your issue has been created with the title '{}'.".format(
            issue_title
        )
    )'''

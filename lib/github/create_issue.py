import os
import json
import datetime
import time
import urllib2

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


def request_connection(hashed_string, date_created=datetime.datetime.today()):

    def __create_title(s):
        return s[:9]

    issue_title = "Hash guarantee ({})".format(__create_title(hashed_string))

    issue_data = {
        "title": issue_title,
        "body": open("{}/lib/github/template".format(os.getcwd())).read().format(
            hashed_string, date_created
        ),
        "labels": ["hash guarantee", "algorithm issue"]
    }

    req = urllib2.Request(
        url="https://api.github.com/repos/ekultek/Dagon/issues", data=json.dumps(issue_data),
        headers={"Authorization": "token {}".format(__handle(__get_encoded_string()))})

    urllib2.urlopen(req).read()
    lib.settings.LOGGER.info(
            "Created issue with title: '{}' at {}..".format(issue_title, time.strftime("%H:%M:%S"))
    )



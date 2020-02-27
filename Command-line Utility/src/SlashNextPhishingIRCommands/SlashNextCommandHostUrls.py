#!/usr/bin/env python
#
# Copyright (C) SlashNext, Inc. (www.slashnext.com)
#
# License:     Subject to the terms and conditions of SlashNext EULA, SlashNext grants to Customer a non-transferable,
#              non-sublicensable, non-exclusive license to use the Software as expressly permitted in accordance with
#              Documentation or other specifications published by SlashNext. The Software is solely for Customer's
#              internal business purposes. All other rights in the Software are expressly reserved by SlashNext.
#

"""
Created on January 22, 2020

@author: Saadat Abid
"""
from getopt import getopt, GetoptError
import sys
from SlashNextPhishingIR.SlashNextHostUrls import SlashNextHostUrls
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_host_urls_table


class SlashNextCommandHostUrls(SlashNextCommand):
    """
    This class implements the 'slashnext-host-urls' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandHostUrls class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__host_urls_action = SlashNextHostUrls(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__host_urls_action)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:h:l:VH",
                ["api_key=", "base_url=", "host=", "limit=", "version", "help"])

            host = None
            api_key = None
            limit = None

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-h', '--host'):
                    host = arg
                elif opt in ('-l', '--limit'):
                    limit = arg
                elif opt in ('-a', '--api_key'):
                    api_key = arg
                elif opt in ('-b', '--base_url'):
                    self.__base_url = arg
                else:
                    print(self.usage)
                    return

            if api_key is None or host is None:
                print(self.usage)
                return
            else:
                self.__api_key = api_key

            self.__host_urls_action = SlashNextHostUrls(
                api_key=self.__api_key, base_url=self.__base_url)

            if limit is None:
                state, response_list = self.__host_urls_action.execution(host=host)
            else:
                state, response_list = self.__host_urls_action.execution(host=host, limit=limit)

            if state == 'Success':
                host_urls_table = get_host_urls_table(response_list)
                print(f'\n{self.__host_urls_action.title}\n\nhost={host}\n\n{host_urls_table}\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandHostUrls()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

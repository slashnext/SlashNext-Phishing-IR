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
Created on August 6, 2021

@author: Saadat Abid
"""
from getopt import getopt, GetoptError
import sys
from SlashNextPhishingIR.SlashNextUrlReputation import SlashNextUrlReputation
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_url_reputation_table


class SlashNextCommandUrlReputation(SlashNextCommand):
    """
    This class implements the 'slashnext-url-reputation' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandUrlReputation class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__url_reputation_action = SlashNextUrlReputation(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__url_reputation_action)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:u:VH",
                ["api_key=", "base_url=", "url=", "version", "help"])

            url = None
            api_key = None

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-u', '--url'):
                    url = arg
                elif opt in ('-a', '--api_key'):
                    api_key = arg
                elif opt in ('-b', '--base_url'):
                    self.__base_url = arg
                else:
                    print(self.usage)
                    return

            if api_key is None or url is None:
                print(self.usage)
                return
            else:
                self.__api_key = api_key

            self.__url_reputation_action = SlashNextUrlReputation(
                api_key=self.__api_key, base_url=self.__base_url)

            state, response_list = self.__url_reputation_action.execution(url=url)

            if state == 'Success':
                url_reputation_table = get_url_reputation_table(response_list)
                print(f'\n{self.__url_reputation_action.title}\n\nurl={url}\n\n{url_reputation_table}\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandUrlReputation()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

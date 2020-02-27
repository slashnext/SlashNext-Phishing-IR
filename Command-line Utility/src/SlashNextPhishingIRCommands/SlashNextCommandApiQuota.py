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
from SlashNextPhishingIR.SlashNextApiQuota import SlashNextApiQuota
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_api_quota_table


class SlashNextCommandApiQuota(SlashNextCommand):
    """
    This class implements the 'slashnext-api-quota' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandApiQuota class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__api_quota_action = SlashNextApiQuota(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__api_quota_action)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:VH",
                ["api_key=", "base_url=", "version", "help"])

            api_key = None

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-a', '--api_key'):
                    api_key = arg
                elif opt in ('-b', '--base_url'):
                    self.__base_url = arg
                else:
                    print(self.usage)
                    return

            if api_key is None:
                print(self.usage)
                return
            else:
                self.__api_key = api_key

            self.__api_quota_action = SlashNextApiQuota(
                api_key=self.__api_key, base_url=self.__base_url)

            state, response_list = self.__api_quota_action.execution()
            if state == 'Success':
                api_quota_table = get_api_quota_table(response_list)
                print(f'\n{self.__api_quota_action.title}\n\n{api_quota_table}\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandApiQuota()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

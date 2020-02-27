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
from SlashNextPhishingIR.SlashNextHostReputation import SlashNextHostReputation
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_host_reputation_table


class SlashNextCommandHostReputation(SlashNextCommand):
    """
    This class implements the 'slashnext-host-reputation' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandHostReputation class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__host_reputation_action = SlashNextHostReputation(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__host_reputation_action)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:h:VH",
                ["api_key=", "base_url=", "host=", "version", "help"])

            host = None
            api_key = None

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-h', '--host'):
                    host = arg
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

            self.__host_reputation_action = SlashNextHostReputation(
                api_key=self.__api_key, base_url=self.__base_url)

            state, response_list = self.__host_reputation_action.execution(host=host)
            if state == 'Success':
                host_reputation_table = get_host_reputation_table(response_list)
                print(f'\n{self.__host_reputation_action.title}\n\nhost={host}\n\n{host_reputation_table}\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandHostReputation()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

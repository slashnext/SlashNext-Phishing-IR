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
from SlashNextPhishingIR.SlashNextUrlScan import SlashNextUrlScan
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_url_scan_table


class SlashNextCommandUrlScan(SlashNextCommand):
    """
    This class implements the 'slashnext-url-scan' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandUrlScan class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__url_scan_action = SlashNextUrlScan(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__url_scan_action)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:u:e:VH",
                ["api_key=", "base_url=", "url=", "extended_info=", "version", "help"])

            url = None
            api_key = None
            extended_info = None

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-u', '--url'):
                    url = arg
                elif opt in ('-e', '--extended_info'):
                    extended_info = arg
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

            self.__url_scan_action = SlashNextUrlScan(
                api_key=self.__api_key, base_url=self.__base_url)

            if extended_info is None:
                state, response_list = self.__url_scan_action.execution(url=url)
            else:
                state, response_list = self.__url_scan_action.execution(url=url, extended_info=extended_info)

            if state == 'Success':
                url_scan_table = get_url_scan_table(response_list)
                print(f'\n{self.__url_scan_action.title}\n\nurl={url}\n\n{url_scan_table}\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandUrlScan()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

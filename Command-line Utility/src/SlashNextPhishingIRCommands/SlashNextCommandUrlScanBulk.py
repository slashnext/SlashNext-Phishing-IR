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
Created on January 15, 2021

@author: Saadat Abid
"""
from getopt import getopt, GetoptError
import sys
from SlashNextPhishingIR.SlashNextUrlScanBulk import SlashNextUrlScanBulk
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_url_scan_bulk_table


class SlashNextCommandUrlScanBulk(SlashNextCommand):
    """
    This class implements the 'slashnext-url-scan-bulk' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandUrlScanBulk class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__url_scan_action_bulk = SlashNextUrlScanBulk(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__url_scan_action_bulk)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:i:o:e:p:r:VH",
                ["api_key=", "base_url=", "input=", "output=", "extended_info=", "poll_interval=", "retries=", "version", "help"])

            input_path = None
            api_key = None
            extended_info = None
            output_path = "."
            poll_interval = 60
            retries = 10

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-i', '--input'):
                    input_path = arg
                elif opt in ('-o', '--output'):
                    output_path = arg
                elif opt in ('-e', '--extended_info'):
                    extended_info = arg
                elif opt in ('-p', '--poll_interval'):
                    poll_interval = int(arg)
                elif opt in ('-r', '--retries'):
                    retries = int(arg)
                elif opt in ('-a', '--api_key'):
                    api_key = arg
                elif opt in ('-b', '--base_url'):
                    self.__base_url = arg
                else:
                    print(self.usage)
                    return

            if api_key is None or input_path is None:
                print(self.usage)
                return
            else:
                self.__api_key = api_key

            self.__url_scan_action_bulk = SlashNextUrlScanBulk(
                api_key=self.__api_key, base_url=self.__base_url)

            if extended_info is None:
                state, response_list = self.__url_scan_action_bulk.execution(input_path=input_path,
                                                                             output_path=output_path,
                                                                             poll_interval=poll_interval,
                                                                             retries=retries)
            else:
                state, response_list = self.__url_scan_action_bulk.execution(input_path=input_path,
                                                                             output_path=output_path,
                                                                             extended_info=extended_info,
                                                                             poll_interval=poll_interval,
                                                                             retries=retries)

            if state in ('Success', 'Quota'):
                if len(response_list):
                    summary = response_list[0]
                    responses = response_list[1:]

                    i_p = summary.get('input')
                    o_p = summary.get('output')
                    url_scan_bulk_table = get_url_scan_bulk_table(summary, responses, o_p)
                    print(f'\n{self.__url_scan_action_bulk.title}\n'
                          f'\nInput file provided at start="{i_p}"'
                          f'\nOutput directory where logs are placed="{o_p}"'
                          f'\n\n{url_scan_bulk_table}\n')

                    if state == 'Quota':
                        print(f'* You have reached the maximum allowed API quota. '
                              f'Please contact SlashNext support at support@slashnext.com\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandUrlScanBulk()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

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
from SlashNextPhishingIR.SlashNextScanReport import SlashNextScanReport
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_scan_report_table


class SlashNextCommandScanReport(SlashNextCommand):
    """
    This class implements the 'slashnext-scan-report' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandScanReport class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__scan_report_action = SlashNextScanReport(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__scan_report_action)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:s:e:VH",
                ["api_key=", "base_url=", "scanid=", "extended_info=", "version", "help"])

            scanid = None
            api_key = None
            extended_info = None

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-s', '--scanid'):
                    scanid = arg
                elif opt in ('-e', '--extended_info'):
                    extended_info = arg
                elif opt in ('-a', '--api_key'):
                    api_key = arg
                elif opt in ('-b', '--base_url'):
                    self.__base_url = arg
                else:
                    print(self.usage)
                    return

            if api_key is None or scanid is None:
                print(self.usage)
                return
            else:
                self.__api_key = api_key

            self.__scan_report_action = SlashNextScanReport(
                api_key=self.__api_key, base_url=self.__base_url)

            if extended_info is None:
                state, response_list = self.__scan_report_action.execution(scanid=scanid)
            else:
                state, response_list = self.__scan_report_action.execution(scanid=scanid, extended_info=extended_info)

            if state == 'Success':
                scan_report_table = get_scan_report_table(response_list)
                print(f'\n{self.__scan_report_action.title}\n\nscanid={scanid}\n\n{scan_report_table}\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandScanReport()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

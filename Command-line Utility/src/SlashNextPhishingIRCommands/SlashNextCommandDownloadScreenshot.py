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
from SlashNextPhishingIR.SlashNextDownloadScreenshot import SlashNextDownloadScreenshot
from .SlashNextCommand import SlashNextCommand
from .SlashNextTables import get_download_sc_file


class SlashNextCommandDownloadScreenshot(SlashNextCommand):
    """
    This class implements the 'slashnext-download-screenshot' command by using the corresponding SlashNext action.
    """
    def __init__(self):
        """
        The constructor for SlashNextCommandDownloadScreenshot class.
        """
        self.__api_key = 'test'
        self.__base_url = 'https://oti.slashnext.cloud/api'
        self.__download_screenshot_action = SlashNextDownloadScreenshot(
            api_key=self.__api_key, base_url=self.__base_url)
        super().__init__(self.__download_screenshot_action)

    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        try:
            opts, args = getopt(
                argv, "a:b:s:r:VH",
                ["api_key=", "base_url=", "scanid=", "resolution=", "version", "help"])

            scanid = None
            api_key = None
            resolution = None

            for opt, arg in opts:
                if opt in ('-V', '--version'):
                    print(self.version)
                    return
                elif opt in ('-s', '--scanid'):
                    scanid = arg
                elif opt in ('-r', '--resolution'):
                    resolution = arg
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

            self.__download_screenshot_action = SlashNextDownloadScreenshot(
                api_key=self.__api_key, base_url=self.__base_url)

            if resolution is None:
                state, response_list = self.__download_screenshot_action.execution(scanid=scanid)
            else:
                state, response_list = self.__download_screenshot_action.execution(scanid=scanid, resolution=resolution)

            if state == 'Success':
                download_sc_table = get_download_sc_file(response_list, scanid)
                print(f'\n{self.__download_screenshot_action.title}\n\nscanid={scanid}\n\n{download_sc_table}\n')
            else:
                print(f'\nERROR: {state}\n')

        except GetoptError:
            print(self.usage)


def run():
    try:
        cmd = SlashNextCommandDownloadScreenshot()
        cmd.execution(sys.argv[1:])
    except:
        exit(0)

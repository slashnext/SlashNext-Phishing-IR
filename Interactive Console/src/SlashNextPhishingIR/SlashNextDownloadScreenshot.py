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
Created on December 10, 2019

@author: Saadat Abid
"""
from .SlashNextAction import SlashNextAction
from .SlashNextAPIs import snx_api_request, DL_SC_API


class SlashNextDownloadScreenshot(SlashNextAction):
    """
    This class implements the 'slashnext-download-screenshot' action by using the 'download/screenshot' SlashNext OTI
    API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextDownloadScreenshot class.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        self.__name = 'slashnext-download-screenshot'
        self.__title = 'SlashNext Phishing Incident Response - Download Screenshot'
        self.__description = 'This action downloads a screenshot of a web page against a previous URL scan request.'
        self.__parameters = [
            {
                'parameter': 'scanid',
                'description': 'Scan ID. Can be retrieved from '
                               'the \"slashnext-url-scan\" action or the \"slashnext-url-scan-sync\" action.'
            },
            {
                'parameter': 'resolution',
                'description': 'Resolution of the web page screenshot. Can be \"high\" or \"medium\". '
                               'Default is \"high\".'
            }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url

    def execution(self, scanid, resolution='high'):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param scanid: Scan ID retrieved from the an earlier call to 'slashnext-url-scan' or 'slashnext-url-scan-sync'.
        :param resolution: Resolution of the web page screenshot.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'scanid': scanid,
            'resolution': resolution,
            'authkey': self.__api_key
        }
        state, response = snx_api_request(self.__base_url, DL_SC_API, api_data)

        return state, [response]

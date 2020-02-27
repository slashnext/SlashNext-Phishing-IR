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
from .SlashNextAPIs import snx_api_request, URL_SCAN_API, DL_SC_API, DL_HTML_API, DL_TEXT_API


class SlashNextUrlScan(SlashNextAction):
    """
    This class implements the 'slashnext-url-scan' action by using the 'url/scan', 'download/screenshot',
    'download/html', and 'download/text' SlashNext OTI API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextUrlScan class.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        self.__name = 'slashnext-url-scan'
        self.__title = 'SlashNext Phishing Incident Response - URL Scan'
        self.__description = 'Performs a real-time URL scan with SlashNext cloud-based SEER Engine. ' \
                             'If the specified URL already exists in the cloud database, scan results will be ' \
                             'returned immediately. If not, this action will submit a URL scan request and return ' \
                             'with the message "check back later" and include a unique Scan ID. You can check the ' \
                             'results of this scan using the "slashnext-scan-report" action anytime after 60 seconds ' \
                             'using the returned Scan ID.'
        self.__parameters = [
            {
                'parameter': 'url',
                'description': 'The URL to scan.'
            },
            {
                'parameter': 'extended_info',
                'description': 'Whether to download forensics data, such as screenshot, HTML, and rendered text. '
                               'If \"true\", forensics data will be returned. If \"false\" (or empty) forensics '
                               'data will not be returned. Default is \"false\".'
            }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url

    def execution(self, url, extended_info='false'):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param url: The URL to scan.
        :param extended_info: Whether to download forensics data, such as screenshot, HTML, and rendered text.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'url': url,
            'authkey': self.__api_key
        }
        state, response = snx_api_request(self.__base_url, URL_SCAN_API, api_data)

        if state != 'Success' or response.get('errorNo') == 1:
            return state, [response]

        if response.get('swlData') is not None and response.get('swlData').get('swlStatus') == 1:
            return state, [response]

        if extended_info == 'true':
            scanid = response.get('urlData').get('scanId')
            api_data = {
                'scanid': scanid,
                'authkey': self.__api_key
            }
            sta_html, response_html = snx_api_request(self.__base_url, DL_HTML_API, api_data)
            sta_text, response_text = snx_api_request(self.__base_url, DL_TEXT_API, api_data)

            api_data['resolution'] = 'medium'
            sta_sc, response_sc = snx_api_request(self.__base_url, DL_SC_API, api_data)

            return state, [response, response_sc, response_html, response_text]
        else:
            return state, [response]

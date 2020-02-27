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


class SlashNextScanReport(SlashNextAction):
    """
    This class implements the 'slashnext-scan-report' action by using the 'url/scan', 'download/screenshot',
    'download/html', and 'download/text' SlashNext OTI API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextScanReport class.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        self.__name = 'slashnext-scan-report'
        self.__title = 'SlashNext Phishing Incident Response - Scan Report'
        self.__description = 'Retrieves the results of a URL scan against a previous scan request. If the scan is ' \
                             'finished, results will be returned immediately; otherwise the message ' \
                             '"check back later" will be returned.'
        self.__parameters = [
            {
                'parameter': 'scanid',
                'description': 'Scan ID. Can be retrieved from '
                               'the \"slashnext-url-scan\" action or the \"slashnext-url-scan-sync\" action.'
            },
            {
                'parameter': 'extended_info',
                'description': 'Whether to download forensics data, such as screenshot, HTML, and rendered text. '
                               'If \"true\", forensics data will be returned. If \"false\" (or empty) forensics data '
                               'will not be returned. Default is \"false\".'
            }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url

    def execution(self, scanid, extended_info='false'):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param scanid: Scan ID retrieved from the an earlier call to 'slashnext-url-scan' or 'slashnext-url-scan-sync'.
        :param extended_info: Whether to download forensics data, such as screenshot, HTML, and rendered text.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'scanid': scanid,
            'authkey': self.__api_key
        }
        state, response = snx_api_request(self.__base_url, URL_SCAN_API, api_data)

        if state != 'Success' or response.get('errorNo') == 1:
            return state, [response]

        if response.get('swlData') is not None and response.get('swlData').get('swlStatus') == 1:
            return state, [response]

        if extended_info == 'true':
            sta_html, response_html = snx_api_request(self.__base_url, DL_HTML_API, api_data)
            sta_text, response_text = snx_api_request(self.__base_url, DL_TEXT_API, api_data)

            api_data['resolution'] = 'medium'
            sta_sc, response_sc = snx_api_request(self.__base_url, DL_SC_API, api_data)

            return state, [response, response_sc, response_html, response_text]
        else:
            return state, [response]

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
from .SlashNextAPIs import snx_api_request, URL_SCANSYNC_API, DL_SC_API, DL_HTML_API, DL_TEXT_API


class SlashNextUrlScanSync(SlashNextAction):
    """
    This class implements the 'slashnext-url-scan-sync' action by using the 'url/scansync', 'download/screenshot',
    'download/html', and 'download/text' SlashNext OTI API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextUrlScanSync class.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        self.__name = 'slashnext-url-scan-sync'
        self.__title = 'SlashNext Phishing Incident Response - URL Scan Sync'
        self.__description = 'Performs a real-time URL scan with SlashNext cloud-based SEER Engine in a blocking ' \
                             'mode. If the specified URL already exists in the cloud database, scan result will be ' \
                             'returned immediately. If not, this action will submit a URL scan request and wait ' \
                             'for the scan to finish. The scan may take up to 60 seconds to finish.'
        self.__parameters = [
            {
                'parameter': 'url',
                'description': 'The URL to scan.'
            },
            {
                'parameter': 'extended_info',
                'description': 'Whether to download forensics data, such as screenshot, HTML, and rendered text. '
                               'If \"true\", forensics data will be returned. If \"false\" (or empty) forensics data '
                               'will not be returned. Default is \"false\".'
            },
            {
                'parameter': 'timeout',
                'description': 'A timeout value in seconds. If the system is unable to complete a scan within the '
                               'specified timeout, a timeout error will be returned. You can run the action again '
                               'with a different timeout. If no timeout value is specified, a default timeout value '
                               'is 60 seconds.'
            }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url

    def execution(self, url, extended_info='false', timeout=60):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param url: The URL to scan.
        :param extended_info: Whether to download forensics data, such as screenshot, HTML, and rendered text.
        :param timeout: A timeout value in seconds. If no timeout value is specified, a default timeout is 60 seconds.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'url': url,
            'timeout': timeout,
            'authkey': self.__api_key
        }
        state, response = snx_api_request(self.__base_url, URL_SCANSYNC_API, api_data)

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

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
from .SlashNextAPIs import snx_api_request, URL_SCANSYNC_API, DL_SC_API, DL_HTML_API, DL_TEXT_API


class SlashNextUrlScanSync:
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
        self.api_key = api_key
        self.base_url = base_url

    def name(self):
        """
        Gets the name string of the action.

        :return: Name of the action.
        """
        return 'slashnext-url-scan-sync'

    def title(self):
        """
        Gets the output title string of the action.

        :return: Output title of the action.
        """
        return 'SlashNext Phishing Incident Response - URL Scan Sync'

    def description(self):
        """
        Gets the description string of the action which explains what the action do exactly.

        :return: Description of the action.
        """
        return 'Performs a real-time URL scan with SlashNext cloud-based SEER Engine in a blocking mode. ' \
               'If the specified URL already exists in the cloud database, scan result will be returned ' \
               'immediately. If not, this command will submit a URL scan request and wait for the scan to ' \
               'finish. The scan may take up to 60 seconds to finish.'

    def parameters(self):
        """
        Gets the list of the parameters accepted by the action.

        :return: List of parameters accepted for the action.
        """
        url = {
            'parameter': 'url',
            'description': 'The URL to scan.'
        }

        extended_info = {
            'parameter': 'extended_info',
            'description': 'Whether to download forensics data, such as screenshot, HTML, and rendered text. '
                           'If \"true\", forensics data will be returned. If \"false\" (or empty) forensics data will '
                           'not be returned. Default is \"false\".'
        }

        timeout = {
            'parameter': 'timeout',
            'description': 'A timeout value in seconds. If the system is unable to complete a scan within the '
                           'specified timeout, a timeout error will be returned. You can run the action again with a '
                           'different timeout. If no timeout value is specified, a default timeout value is 60 seconds.'
        }

        return [url, extended_info, timeout]

    def help(self):
        """
        Gets the help string of action which gives details on how to execute the action.

        :return: Help on the action.
        """
        help_str = '\nACTION: ' + self.name() + '\n  ' + self.description() + '\n'
        help_str += '\nPARAMETERS: \n'
        param_list = self.parameters()
        for param in param_list:
            help_str += '<' + param.get('parameter') + '>\n  ' + param.get('description') + '\n'

        return help_str

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
            'authkey': self.api_key
        }
        state, response = snx_api_request(self.base_url, URL_SCANSYNC_API, api_data)

        if state != 'Success' or response.get('errorNo') == 1:
            return state, [response]

        if response.get('swlData') is not None:
            if response.get('swlData').get('swlStatus') == 1:
                return state, [response]

        if extended_info == 'true':
            scanid = response.get('urlData').get('scanId')
            api_data = {
                'scanid': scanid,
                'authkey': self.api_key
            }
            sta_html, response_html = snx_api_request(self.base_url, DL_HTML_API, api_data)
            sta_text, response_text = snx_api_request(self.base_url, DL_TEXT_API, api_data)

            api_data['resolution'] = 'medium'
            sta_sc, response_sc = snx_api_request(self.base_url, DL_SC_API, api_data)

            return state, [response, response_sc, response_html, response_text]
        else:
            return state, [response]

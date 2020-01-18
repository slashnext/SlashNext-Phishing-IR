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
from .SlashNextAPIs import snx_api_request, DL_HTML_API


class SlashNextDownloadHtml:
    """
    This class implements the 'slashnext-download-html' action by using the 'download/html' SlashNext OTI API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextDownloadHtml class.

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
        return 'slashnext-download-html'

    def title(self):
        """
        Gets the output title string of the action.

        :return: Output title of the action.
        """
        return 'SlashNext Phishing Incident Response - Download HTML'

    def description(self):
        """
        Gets the description string of the action which explains what the action do exactly.

        :return: Description of the action.
        """
        return 'This action downloads a web page HTML against a previous URL scan request.'

    def parameters(self):
        """
        Gets the list of the parameters accepted by the action.

        :return: List of parameters accepted for the action.
        """
        scanid = {
            'parameter': 'scanid',
            'description': 'Scan ID. Can be retrieved from '
                           'the \"slashnext-url-scan\" action or the \"slashnext-url-scan-sync\" action.'
        }

        return [scanid]

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

    def execution(self, scanid):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param scanid: Scan ID retrieved from the an earlier call to 'slashnext-url-scan' or 'slashnext-url-scan-sync'.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'scanid': scanid,
            'authkey': self.api_key
        }
        state, response = snx_api_request(self.base_url, DL_HTML_API, api_data)

        return state, [response]

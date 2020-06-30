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
from .SlashNextAPIs import (
    snx_api_request, HOST_REPUTE_API, HOST_REPORT_API, URL_SCANSYNC_API, DL_SC_API, DL_HTML_API, DL_TEXT_API)


class SlashNextHostReport(SlashNextAction):
    """
    This class implements the 'slashnext-host-report' action by using the 'host/reputation', 'host/report',
    'url/scansync', 'download/screenshot', 'download/html', and 'download/text' SlashNext OTI API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextHostReport class.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        self.__name = 'slashnext-host-report'
        self.__title = 'SlashNext Phishing Incident Response - Host Report'
        self.__description = 'This action queries the SlashNext cloud database and retrieves a detailed report for ' \
                             'a host and associated URL.'
        self.__parameters = [
            {
                'parameter': 'host',
                'description': 'The host to look up in the SlashNext Threat Intelligence database. '
                               'Can be either a domain name or an IPv4 address.'
            }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url

    def execution(self, host):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param host: The host to look up in the SlashNext Threat Intelligence database.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'host': host,
            'authkey': self.__api_key
        }
        state, response = snx_api_request(self.__base_url, HOST_REPUTE_API, api_data)

        if state != 'Success':
            return state, [response]

        api_data = {
            'host': host,
            'page': 1,
            'rpp': 1,
            'authkey': self.__api_key
        }
        sta_, response_ = snx_api_request(self.__base_url, HOST_REPORT_API, api_data)

        if sta_ != 'Success':
            return state, [response]

        url_data = response_.get('urlDataList')[0]
        scanid = url_data.get('scanId')
        if scanid == 'N/A':
            api_data = {
                'url': url_data.get('url'),
                'timeout': 60,
                'authkey': self.__api_key
            }
            sta_, response_ = snx_api_request(self.__base_url, URL_SCANSYNC_API, api_data)

            if sta_ != 'Success':
                return state, [response]

            if response_.get('swlData') is not None and response_.get('swlData').get('swlStatus') == 1:
                return state, [response]

            url_data = response_.get('urlData')
            scanid = url_data.get('scanId')

        api_data = {
            'scanid': scanid,
            'authkey': self.__api_key
        }
        sta_html, response_html = snx_api_request(self.__base_url, DL_HTML_API, api_data)
        sta_text, response_text = snx_api_request(self.__base_url, DL_TEXT_API, api_data)

        api_data['resolution'] = 'medium'
        sta_sc, response_sc = snx_api_request(self.__base_url, DL_SC_API, api_data)

        return state, [response, response_, response_sc, response_html, response_text]

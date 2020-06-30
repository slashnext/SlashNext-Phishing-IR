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
from .SlashNextAPIs import snx_api_request, HOST_REPORT_API


class SlashNextHostUrls(SlashNextAction):
    """
    This class implements the 'slashnext-host-urls' action by using the 'host/report' SlashNext OTI API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextHostUrls class.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        self.__name = 'slashnext-host-urls'
        self.__title = 'SlashNext Phishing Incident Response - Host URLs'
        self.__description = 'This action queries the SlashNext cloud database and retrieves a list of all URLs ' \
                             'associated with the specified host.'
        self.__parameters = [
            {
                'parameter': 'host',
                'description': 'The host to look up in the SlashNext Threat Intelligence database, for which to return '
                               'a list of associated URLs. Can be either a domain name or an IPv4 address.'
            },
            {
                'parameter': 'limit',
                'description': 'The maximum number of URL records to fetch. Default is 10.'
            }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url

    def execution(self, host, limit=10):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param host: The host to look up in the SlashNext Threat Intelligence database.
        :param limit: The maximum number of URL records to fetch. Default is 10.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'host': host,
            'page': 1,
            'rpp': limit,
            'authkey': self.__api_key
        }
        state, response = snx_api_request(self.__base_url, HOST_REPORT_API, api_data)

        return state, [response]

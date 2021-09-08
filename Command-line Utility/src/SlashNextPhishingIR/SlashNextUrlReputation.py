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
Created on August 5, 2021

@author: Saadat Abid
"""
from .SlashNextAction import SlashNextAction
from .SlashNextAPIs import snx_api_request, URL_REPUTE_API


class SlashNextUrlReputation(SlashNextAction):
    """
    This class implements the 'slashnext-url-reputation' action by using the 'url/reputation' SlashNext OTI API.

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
        self.__name = 'slashnext-url-reputation'
        self.__title = 'SlashNext Phishing Incident Response - URL Reputation'
        self.__description = 'This action queries the SlashNext cloud database and retrieves the reputation of a URL.'
        self.__parameters = [
            {
                'parameter': 'url',
                'description': 'The URL to look up in the SlashNext Threat Intelligence database.'
            }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url

    def execution(self, url):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param url: The URL to look up in the SlashNext Threat Intelligence database.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        api_data = {
            'url': url,
            'authkey': self.__api_key
        }
        state, response = snx_api_request(self.__base_url, URL_REPUTE_API, api_data)

        return state, [response]


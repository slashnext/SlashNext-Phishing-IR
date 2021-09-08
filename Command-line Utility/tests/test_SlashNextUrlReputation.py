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
import unittest
from unittest.mock import patch, Mock
from src.SlashNextPhishingIR.SlashNextUrlReputation import SlashNextUrlReputation


class TestSlashNextUrlReputation(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextUrlReputation class which is using url/reputation OTI API.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextUrlReputation" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        print('\n\nSetting up test pre-conditions with a "valid" API key and a "valid" API base URL.')

        # Set of valid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'
        self.url = 'https://google.com/'

        # Set of valid expected outputs
        self.name = 'slashnext-url-reputation'
        self.title = 'SlashNext Phishing Incident Response - URL Reputation'
        self.description = 'This action queries the SlashNext cloud database and retrieves the reputation of a URL.'
        self.parameters = [
            {
                'parameter': 'url',
                'description': 'The URL to look up in the SlashNext Threat Intelligence database.'
            }
        ]
        self.help = '\nACTION: ' + self.name + '\n  ' + self.description + '\n'
        self.help += '\nPARAMETERS: \n'
        for param in self.parameters:
            self.help += '<' + param.get('parameter') + '>\n  ' + param.get('description') + '\n'

        self.api_url_reputation = 'https://oti.slashnext.cloud/api/oti/v1/url/reputation'
        self.api_data_reputation = {
            'authkey': self.api_key,
            'url': self.url
        }
        self.reputation_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "urlData": {
                "url": "https://google.com/",
                "threatData": {
                    "verdict": "Benign",
                    "threatStatus": "N/A",
                    "threatName": "N/A",
                    "threatType": "N/A",
                    "firstSeen": "08-27-2019 10:32:19 UTC",
                    "lastSeen": "08-27-2019 12:34:52 UTC"
                }
            },
            "normalizeData": {
                "normalizeStatus": 0,
                "normalizeMessage": ""
            }
        }

        self.state = 'Success'
        self.response_list = [self.reputation_response]

        self.url_reputation_action = SlashNextUrlReputation(api_key=self.api_key, base_url=self.base_url)

    def test_name(self):
        """
        Test the results of name property of class SlashNextUrlReputation.
        """
        print(f'{self.test_name.__name__}'
              f': Executing unit test for property "name" of class "SlashNextUrlReputation".')

        self.assertEqual(self.url_reputation_action.name, self.name)

    def test_title(self):
        """
        Test the results of title property of class SlashNextUrlReputation.
        """
        print(f'{self.test_title.__name__}'
              f': Executing unit test for property "title" of class "SlashNextUrlReputation".')

        self.assertEqual(self.url_reputation_action.title, self.title)

    def test_description(self):
        """
        Test the results of description property of class SlashNextUrlReputation.
        """
        print(f'{self.test_description.__name__}'
              f': Executing unit test for property "description" of class "SlashNextUrlReputation".')

        self.assertEqual(self.url_reputation_action.description, self.description)

    def test_parameters(self):
        """
        Test the results of parameters property of class SlashNextUrlReputation.
        """
        print(f'{self.test_parameters.__name__}'
              f': Executing unit test for property "parameters" of class "SlashNextUrlReputation".')

        self.assertEqual(self.url_reputation_action.parameters, self.parameters)

    def test_help(self):
        """
        Test the results of help property of class SlashNextUrlReputation.
        """
        print(f'{self.test_help.__name__}'
              f': Executing unit test for property "help" of class "SlashNextUrlReputation".')

        self.assertEqual(self.url_reputation_action.help, self.help)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextUrlReputation.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextUrlReputation".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.reputation_response)

            state, response_list = self.url_reputation_action.execution(url=self.url)

            mocked_request.assert_called_with('POST',
                                              url=self.api_url_reputation,
                                              data=self.api_data_reputation,
                                              timeout=300)

            self.assertEqual(mocked_request.call_count, 1)

        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list)

    def tearDown(self):
        """
        This shall be invoked at the end of each test execution contained within this class.
        """
        pass

    @classmethod
    def tearDownClass(cls):
        """
        This shall be invoked only once at the end of the tests execution contained within this class.
        """
        print('\n\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Finished the execution of tests for class "SlashNextUrlReputation" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

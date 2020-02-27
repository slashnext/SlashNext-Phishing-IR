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
Created on January 22, 2020

@author: Saadat Abid
"""
import unittest
from unittest.mock import patch, Mock
from src.SlashNextPhishingIR.SlashNextDownloadText import SlashNextDownloadText


class TestSlashNextDownloadText(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextDownloadText class which is using download/text OTI API.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextDownloadText" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        print('\n\nSetting up test pre-conditions with a "valid" API key and a "valid" API base URL.')

        # Set of valid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'
        self.scanid = 'cc4115b3-2064-4212-a644-871645d94132'

        # Set of valid expected outputs
        self.name = 'slashnext-download-text'
        self.title = 'SlashNext Phishing Incident Response - Download Text'
        self.description = 'This action downloads the text of a web page against a previous URL scan request.'
        self.parameters = [
            {
                'parameter': 'scanid',
                'description': 'Scan ID. Can be retrieved from '
                               'the \"slashnext-url-scan\" action or the \"slashnext-url-scan-sync\" action.'
            }
        ]
        self.help = '\nACTION: ' + self.name + '\n  ' + self.description + '\n'
        self.help += '\nPARAMETERS: \n'
        for param in self.parameters:
            self.help += '<' + param.get('parameter') + '>\n  ' + param.get('description') + '\n'

        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/download/text'
        self.api_data = {
            'authkey': self.api_key,
            'scanid': self.scanid,
        }
        self.text_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "textData": {
                "textBase64": "test data",
                "textName": "Webpage-text"
            }
        }

        self.state = 'Success'
        self.response_list = [self.text_response]

        self.download_text_action = SlashNextDownloadText(api_key=self.api_key, base_url=self.base_url)

    def test_name(self):
        """
        Test the results of name property of class SlashNextDownloadText.
        """
        print(f'{self.test_name.__name__}'
              f': Executing unit test for property "name" of class "SlashNextDownloadText".')

        self.assertEqual(self.download_text_action.name, self.name)

    def test_title(self):
        """
        Test the results of title property of class SlashNextDownloadText.
        """
        print(f'{self.test_title.__name__}'
              f': Executing unit test for property "title" of class "SlashNextDownloadText".')

        self.assertEqual(self.download_text_action.title, self.title)

    def test_description(self):
        """
        Test the results of description property of class SlashNextDownloadText.
        """
        print(f'{self.test_description.__name__}'
              f': Executing unit test for property "description" of class "SlashNextDownloadText".')

        self.assertEqual(self.download_text_action.description, self.description)

    def test_parameters(self):
        """
        Test the results of parameters property of class SlashNextDownloadText.
        """
        print(f'{self.test_parameters.__name__}'
              f': Executing unit test for property "parameters" of class "SlashNextDownloadText".')

        self.assertEqual(self.download_text_action.parameters, self.parameters)

    def test_help(self):
        """
        Test the results of help property of class SlashNextDownloadText.
        """
        print(f'{self.test_help.__name__}'
              f': Executing unit test for property "help" of class "SlashNextDownloadText".')

        self.assertEqual(self.download_text_action.help, self.help)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextDownloadText.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextDownloadText".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.text_response)

            state, response_list = self.download_text_action.execution(scanid=self.scanid)

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

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
        print('Finished the execution of tests for class "SlashNextDownloadText" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

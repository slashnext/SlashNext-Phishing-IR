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
Created on Feb 06, 2020

@author: Saadat Abid
"""
import unittest
from unittest.mock import patch, Mock
from src.SlashNextPhishingIRCommands.SlashNextCommandHostReport import SlashNextCommandHostReport


class TestSlashNextCommandHostReport(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextCommandHostReport class.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextCommandHostReport" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        print('\n\nSetting up test pre-conditions.')

        # Set of valid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'
        self.host = 'www.google.com'

        # Set of valid expected outputs
        self.name = 'slashnext-host-report'
        self.description = 'This action queries the SlashNext cloud database and retrieves a detailed report for ' \
                           'a host and associated URL.'
        self.parameters = [
            {
                'parameter': 'host',
                'description': 'The host to look up in the SlashNext Threat Intelligence database. '
                               'Can be either a domain name or an IPv4 address.'
            }
        ]

        self.version = f'\nv1.1.0'
        self.version += f'\nDeveloped by SlashNext, Inc. (support@slashnext.com)\n'

        self.usage = f'\n{self.description}\n\n'
        self.usage += f'Usage: {self.name} -a [api_key] -b [base_url]'
        for param in self.parameters:
            self.usage += f' -{param.get("parameter")[0]} [{param.get("parameter")}]'

        self.usage += f'\n'
        self.usage += f' -a   --api_key          Please provide a valid API Key or contact support@slashnext.com\n'
        self.usage += f' -b   --base_url         Please provide a valid Base URL or contact support@slashnext.com\n'
        for param in self.parameters:
            param_name = param.get("parameter")
            param_desc = param.get("description")
            self.usage += ' -{0}   --{1:16} {2}\n'.format(param_name[0], param_name, param_desc)

        self.usage += f' -V   --version          Version of SlashNext phishing IR commands.\n'
        self.usage += f' -H   --help             Prints this help/usage.\n'
        self.usage += f'\nDeveloped by SlashNext, Inc. (support@slashnext.com)\n'

        self.api_url_reputation = 'https://oti.slashnext.cloud/api/oti/v1/host/reputation'
        self.api_data_reputation = {
            'authkey': self.api_key,
            'host': self.host
        }
        self.reputation_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "threatData": {
                "verdict": "Benign",
                "threatStatus": "N/A",
                "threatName": "N/A",
                "threatType": "N/A",
                "firstSeen": "12-10-2020 13:04:17 UTC",
                "lastSeen": "01-13-2020 11:18:15 UTC"
            }
        }

        self.api_url_report = 'https://oti.slashnext.cloud/api/oti/v1/host/report'
        self.api_data_report = {
            'authkey': self.api_key,
            'host': self.host,
            'page': 1,
            'rpp': 1
        }
        self.report_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "urlDataList": [
                {
                    "url": "https://google.com/",
                    "scanId": "cc4115b3-2064-4212-a644-871645d94132",
                    "threatData": {
                        "verdict": "Benign",
                        "threatStatus": "N/A",
                        "threatName": "N/A",
                        "threatType": "N/A",
                        "firstSeen": "08-27-2019 10:32:19 UTC",
                        "lastSeen": "08-27-2019 12:34:52 UTC"
                    }
                }
            ],
            "normalizeData": {
                "normalizeStatus": 0,
                "normalizeMessage": ""
            }
        }

        self.api_url_sc = 'https://oti.slashnext.cloud/api/oti/v1/download/screenshot'
        self.api_data = {
            'authkey': self.api_key,
            'scanid': self.report_response['urlDataList'][0].get('scanId'),
            'resolution': 'medium'
        }
        self.sc_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "scData": {
                "scBase64": "test data",
                "scName": "Webpage-screenshot",
                "scContentType": "jpeg"
            }
        }

        self.api_url_html = 'https://oti.slashnext.cloud/api/oti/v1/download/html'
        self.html_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "htmlData": {
                "htmlBase64": "test data",
                "htmlName": "Webpage-html",
                "htmlContenType": "html"
            }
        }

        self.api_url_text = 'https://oti.slashnext.cloud/api/oti/v1/download/text'
        self.text_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "textData": {
                "textBase64": "test data",
                "textName": "Webpage-text"
            }
        }

        self.host_report_command = SlashNextCommandHostReport()

    def test_usage(self):
        """
        Test the results of usage property of class SlashNextCommandHostReport.
        """
        print(f'{self.test_usage.__name__}'
              f': Executing unit test for property "usage" of class "SlashNextCommandHostReport".')

        self.assertEqual(self.host_report_command.usage, self.usage)

    def test_version(self):
        """
        Test the results of version property of class SlashNextCommandHostReport.
        """
        print(f'{self.test_version.__name__}'
              f': Executing unit test for property "version" of class "SlashNextCommandHostReport".')

        self.assertEqual(self.host_report_command.version, self.version)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextCommandHostReport.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextCommandHostReport".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            self.host_report_command.execution(argv=['-a', self.api_key,
                                                     '-h', self.host])

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_reputation,
                                           data=self.api_data_reputation,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_report,
                                           data=self.api_data_report,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_sc,
                                           data=self.api_data,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_html,
                                           data=self.api_data,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_text,
                                           data=self.api_data,
                                           timeout=300)

            self.assertEqual(mocked_request.call_count, 5)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            self.host_report_command.execution(argv=['-a', self.api_key,
                                                     '-b', 'https://test/api',
                                                     '-h', self.host])

            mocked_request.assert_any_call('POST',
                                           url='https://test/api/oti/v1/host/reputation',
                                           data=self.api_data_reputation,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url='https://test/api/oti/v1/host/report',
                                           data=self.api_data_report,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url='https://test/api/oti/v1/download/screenshot',
                                           data=self.api_data,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url='https://test/api/oti/v1/download/html',
                                           data=self.api_data,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url='https://test/api/oti/v1/download/text',
                                           data=self.api_data,
                                           timeout=300)

            self.assertEqual(mocked_request.call_count, 5)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            self.host_report_command.execution(argv=['--api_key', self.api_key,
                                                     '--base_url', self.base_url,
                                                     '--host', self.host])

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_reputation,
                                           data=self.api_data_reputation,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_report,
                                           data=self.api_data_report,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_sc,
                                           data=self.api_data,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_html,
                                           data=self.api_data,
                                           timeout=300)

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_text,
                                           data=self.api_data,
                                           timeout=300)

            self.assertEqual(mocked_request.call_count, 5)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            self.host_report_command.execution(argv=['-V'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            self.host_report_command.execution(argv=['-H'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            self.host_report_command.execution(argv=['-a', self.api_key])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            self.host_report_command.execution(argv=['--invalid', 'Wrong Option'])

            mocked_request.assert_not_called()

        # Invalid key
        self.api_key = 'this_is_an_invalid_api_key'
        self.api_data = {
            'authkey': self.api_key,
            'host': self.host
        }
        self.reputation_response = {
            "errorNo": 7002,
            "errorMsg": "The system is unable to authenticate your request, please provide a valid API key."
        }

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.reputation_response)

            self.host_report_command.execution(argv=['-a', self.api_key,
                                                     '-h', self.host])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url_reputation,
                                              data=self.api_data,
                                              timeout=300)

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
        print('Finished the execution of tests for class "SlashNextCommandHostReport" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

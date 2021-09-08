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
from src.SlashNextPhishingIRCommands.SlashNextCommandHostUrls import SlashNextCommandHostUrls


class TestSlashNextCommandHostUrls(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextCommandHostUrls class.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextCommandHostUrls" with valid set of inputs.')
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
        self.limit = 5

        # Set of valid expected outputs
        self.name = 'slashnext-host-urls'
        self.description = 'This action queries the SlashNext cloud database and retrieves a list of all URLs ' \
                           'associated with the specified host.'
        self.parameters = [
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

        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/host/report'
        self.api_data = {
            'authkey': self.api_key,
            'host': self.host,
            'page': 1,
            'rpp': self.limit
        }
        self.api_data_default = {
            'authkey': self.api_key,
            'host': self.host,
            'page': 1,
            'rpp': 10
        }
        self.urls_response = {
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
                },
                {
                    "url": "https://google.com/about",
                    "scanId": "0d230a3f-fffd-4608-a120-41a952c69367",
                    "threatData": {
                        "verdict": "Redirector",
                        "threatStatus": "N/A",
                        "threatName": "N/A",
                        "threatType": "N/A",
                        "firstSeen": "01-01-2020 08:03:37 UTC",
                        "lastSeen": "01-01-2020 08:04:04 UTC"
                    },
                    "landingUrl": {
                        "url": "https://about.google/",
                        "scanId": "d97ea14c-bac1-4eec-b5d2-c6989c038231",
                        "threatData": {
                            "verdict": "Benign",
                            "threatStatus": "N/A",
                            "threatType": "N/A",
                            "threatName": "N/A",
                            "firstSeen": "01-01-2020 07:19:10 UTC",
                            "lastSeen": "01-01-2020 07:19:10 UTC"
                        }
                    }
                },
                {
                    "url": "http://www.google.com/about",
                    "scanId": "d08fc9cf-ca06-4d85-881d-63788e922fa5",
                    "threatData": {
                        "verdict": "Redirector",
                        "threatStatus": "N/A",
                        "threatName": "N/A",
                        "threatType": "N/A",
                        "firstSeen": "01-01-2020 08:03:37 UTC",
                        "lastSeen": "01-01-2020 08:04:04 UTC"
                    },
                    "landingUrl": {
                        "url": "https://about.google/",
                        "scanId": "61ed630d-bce6-4c27-a844-587614c8aefa",
                        "threatData": {
                            "verdict": "Benign",
                            "threatStatus": "N/A",
                            "threatType": "N/A",
                            "threatName": "N/A",
                            "firstSeen": "01-01-2020 07:19:10 UTC",
                            "lastSeen": "01-01-2020 07:19:10 UTC"
                        }
                    }
                },
                {
                    "url": "http://google.com/about",
                    "scanId": "e61a64ec-2f03-4f8b-8291-58ce2f2b2b17",
                    "threatData": {
                        "verdict": "Redirector",
                        "threatStatus": "N/A",
                        "threatName": "N/A",
                        "threatType": "N/A",
                        "firstSeen": "01-01-2020 08:03:37 UTC",
                        "lastSeen": "01-01-2020 08:04:04 UTC"
                    },
                    "landingUrl": {
                        "url": "https://about.google/",
                        "scanId": "7fdf9d1f-6904-4cd3-a904-27600fc0901b",
                        "threatData": {
                            "verdict": "Benign",
                            "threatStatus": "N/A",
                            "threatType": "N/A",
                            "threatName": "N/A",
                            "firstSeen": "01-01-2020 07:19:10 UTC",
                            "lastSeen": "01-01-2020 07:19:10 UTC"
                        }
                    }
                },
                {
                    "url": "http://google.com/",
                    "scanId": "800d3a85-c4f7-4fb7-86c5-d894c529f774",
                    "threatData": {
                        "verdict": "Benign",
                        "threatStatus": "N/A",
                        "threatName": "N/A",
                        "threatType": "N/A",
                        "firstSeen": "08-26-2019 17:29:38 UTC",
                        "lastSeen": "08-26-2019 19:41:19 UTC"
                    },
                    "finalUrl": "https://www.google.com/?gws_rd=ssl"
                }
            ],
            "normalizeData": {
                "normalizeStatus": 0,
                "normalizeMessage": ""
            }
        }

        self.host_urls_command = SlashNextCommandHostUrls()

    def test_usage(self):
        """
        Test the results of usage property of class SlashNextCommandHostUrls.
        """
        print(f'{self.test_usage.__name__}'
              f': Executing unit test for property "usage" of class "SlashNextCommandHostUrls".')

        self.assertEqual(self.host_urls_command.usage, self.usage)

    def test_version(self):
        """
        Test the results of version property of class SlashNextCommandHostUrls.
        """
        print(f'{self.test_version.__name__}'
              f': Executing unit test for property "version" of class "SlashNextCommandHostUrls".')

        self.assertEqual(self.host_urls_command.version, self.version)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextCommandHostUrls.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextCommandHostUrls".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['-a', self.api_key,
                                                   '-h', self.host])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data_default,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['-a', self.api_key,
                                                   '-h', self.host,
                                                   '-l', self.limit])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['-a', self.api_key,
                                                   '-b', 'https://test/api',
                                                   '-h', self.host])

            mocked_request.assert_called_with('POST',
                                              url='https://test/api/oti/v1/host/report',
                                              data=self.api_data_default,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['--api_key', self.api_key,
                                                   '--base_url', self.base_url,
                                                   '--host', self.host])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data_default,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['--api_key', self.api_key,
                                                   '--base_url', self.base_url,
                                                   '--host', self.host,
                                                   '--limit', self.limit])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['-V'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['-H'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['-a', self.api_key])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['--invalid', 'Wrong Option'])

            mocked_request.assert_not_called()

        # Invalid key
        self.api_key = 'this_is_an_invalid_api_key'
        self.api_data = {
            'authkey': self.api_key,
            'host': self.host,
            'page': 1,
            'rpp': self.limit
        }
        self.urls_response = {
            "errorNo": 7002,
            "errorMsg": "The system is unable to authenticate your request, please provide a valid API key."
        }

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            self.host_urls_command.execution(argv=['-a', self.api_key,
                                                   '-h', self.host,
                                                   '-l', self.limit])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
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
        print('Finished the execution of tests for class "SlashNextCommandHostUrls" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

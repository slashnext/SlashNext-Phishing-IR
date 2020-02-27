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
from src.SlashNextPhishingIRCommands.SlashNextCommandApiQuota import SlashNextCommandApiQuota


class TestSlashNextCommandApiQuota(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextCommandApiQuota class.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextCommandApiQuota" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        print('\n\nSetting up test pre-conditions.')

        # Set of valid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of valid expected outputs
        self.name = 'slashnext-api-quota'
        self.description = 'This action queries the SlashNext cloud database and retrieves the details of API quota.'
        self.parameters = []

        self.version = f'\nv1.0.0'
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

        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/quota/status'
        self.api_data = {
            'authkey': self.api_key
        }
        self.quota_response = {
            'errorMsg': 'Success',
            'errorNo': 0,
            'quotaDetails': {
                'consumedAPIDetail': {
                    'customerApiQuota': 0,
                    'downloadHTML': 0,
                    'downloadScreenshot': 0,
                    'downloadText': 0,
                    'hostReputation': 0,
                    'hostUrls': 0,
                    'scanReportWithScanId': 0,
                    'scanSyncReportWithScanId': 0,
                    'urlReputation': 0,
                    'urlScan': 0,
                    'urlScanSync': 0
                },
                'consumedPointsDetail': {
                    'customerApiQuota': 0,
                    'downloadHTML': 0,
                    'downloadScreenshot': 0,
                    'downloadText': 0,
                    'hostReputation': 0,
                    'hostUrls': 0,
                    'scanReportWithScanId': 0,
                    'scanSyncReportWithScanId': 0,
                    'urlReputation': 0,
                    'urlScan': 0,
                    'urlScanSync': 0
                },
                'pointsConsumptionRate': {
                    'customerApiQuota': 0,
                    'downloadHTML': 0,
                    'downloadScreenshot': 0,
                    'downloadText': 0,
                    'hostReputation': 1,
                    'hostUrls': 1,
                    'urlReputation': 1,
                    'urlScan': 3,
                    'urlScanSync': 3,
                    'urlScanSyncWithScanId': 0,
                    'urlScanWithScanId': 0
                },
                'expiryDate': '2020-12-19',
                'isExpired': False,
                'licensedQuota': 'Unlimited',
                'remainingQuota': 'Unlimited',
                'note': 'Your annual API quota will be reset to zero, once either the limit is reached or upon quota '
                        'expiration date indicated above.'
            }
        }

        self.api_quota_command = SlashNextCommandApiQuota()

    def test_usage(self):
        """
        Test the results of usage property of class SlashNextCommandApiQuota.
        """
        print(f'{self.test_usage.__name__}'
              f': Executing unit test for property "usage" of class "SlashNextCommandApiQuota".')

        self.assertEqual(self.api_quota_command.usage, self.usage)

    def test_version(self):
        """
        Test the results of version property of class SlashNextCommandApiQuota.
        """
        print(f'{self.test_version.__name__}'
              f': Executing unit test for property "version" of class "SlashNextCommandApiQuota".')

        self.assertEqual(self.api_quota_command.version, self.version)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextCommandApiQuota.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextCommandApiQuota".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=['-a', self.api_key])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=['-a', self.api_key,
                                                   '-b', 'https://test/api'])

            mocked_request.assert_called_with('POST',
                                              url='https://test/api/oti/v1/quota/status',
                                              data=self.api_data,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=['--api_key', self.api_key,
                                                   '--base_url', self.base_url])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=['-V'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=['-H'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=[])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=['--invalid', 'Wrong Option'])

            mocked_request.assert_not_called()

        # Invalid key
        self.api_key = 'this_is_an_invalid_api_key'
        self.api_data = {
            'authkey': self.api_key
        }
        self.quota_response = {
            "errorNo": 7002,
            "errorMsg": "The system is unable to authenticate your request, please provide a valid API key."
        }

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            self.api_quota_command.execution(argv=['-a', self.api_key])

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
        print('Finished the execution of tests for class "SlashNextCommandApiQuota" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

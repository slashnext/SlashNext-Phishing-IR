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
from src.SlashNextPhishingIRCommands.SlashNextCommandDownloadScreenshot import SlashNextCommandDownloadScreenshot


class TestSlashNextCommandDownloadScreenshot(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextCommandDownloadScreenshot class.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextCommandDownloadScreenshot" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        print('\n\nSetting up test pre-conditions.')

        # Set of valid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'
        self.scanid = 'cc4115b3-2064-4212-a644-871645d94132'
        self.resolution = 'medium'

        # Set of valid expected outputs
        self.name = 'slashnext-download-screenshot'
        self.description = 'This action downloads a screenshot of a web page against a previous URL scan request.'
        self.parameters = [
            {
                'parameter': 'scanid',
                'description': 'Scan ID. Can be retrieved from '
                               'the \"slashnext-url-scan\" action or the \"slashnext-url-scan-sync\" action.'
            },
            {
                'parameter': 'resolution',
                'description': 'Resolution of the web page screenshot. Can be \"high\" or \"medium\". '
                               'Default is \"high\".'
            }
        ]

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

        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/download/screenshot'
        self.api_data = {
            'authkey': self.api_key,
            'scanid': self.scanid,
            'resolution': self.resolution
        }
        self.api_data_default = {
            'authkey': self.api_key,
            'scanid': self.scanid,
            'resolution': 'high'
        }
        self.screenshot_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "scData": {
                "scBase64": "test data",
                "scName": "Webpage-screenshot",
                "scContentType": "jpeg"
            }
        }

        self.download_screenshot_command = SlashNextCommandDownloadScreenshot()

    def test_usage(self):
        """
        Test the results of usage property of class SlashNextCommandDownloadScreenshot.
        """
        print(f'{self.test_usage.__name__}'
              f': Executing unit test for property "usage" of class "SlashNextCommandDownloadScreenshot".')

        self.assertEqual(self.download_screenshot_command.usage, self.usage)

    def test_version(self):
        """
        Test the results of version property of class SlashNextCommandDownloadScreenshot.
        """
        print(f'{self.test_version.__name__}'
              f': Executing unit test for property "version" of class "SlashNextCommandDownloadScreenshot".')

        self.assertEqual(self.download_screenshot_command.version, self.version)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextCommandDownloadScreenshot.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextCommandDownloadScreenshot".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['-a', self.api_key,
                                                             '-s', self.scanid])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data_default,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['-a', self.api_key,
                                                             '-s', self.scanid,
                                                             '-r', self.resolution])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['-a', self.api_key,
                                                             '-b', 'https://test/api',
                                                             '-s', self.scanid])

            mocked_request.assert_called_with('POST',
                                              url='https://test/api/oti/v1/download/screenshot',
                                              data=self.api_data_default,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['--api_key', self.api_key,
                                                             '--base_url', self.base_url,
                                                             '--scanid', self.scanid])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data_default,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['--api_key', self.api_key,
                                                             '--base_url', self.base_url,
                                                             '--scanid', self.scanid,
                                                             '--resolution', self.resolution])

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['-V'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['-H'])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['-a', self.api_key])

            mocked_request.assert_not_called()

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['--invalid', 'Wrong Option'])

            mocked_request.assert_not_called()

        # Invalid key
        self.api_key = 'this_is_an_invalid_api_key'
        self.api_data = {
            'authkey': self.api_key,
            'scanid': self.scanid,
            'resolution': self.resolution
        }
        self.screenshot_response = {
            "errorNo": 7002,
            "errorMsg": "The system is unable to authenticate your request, please provide a valid API key."
        }

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            self.download_screenshot_command.execution(argv=['-a', self.api_key,
                                                             '-s', self.scanid,
                                                             '-r', self.resolution])

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
        print('Finished the execution of tests for class "SlashNextCommandDownloadScreenshot" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

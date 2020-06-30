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
from src.SlashNextPhishingIR.SlashNextScanReport import SlashNextScanReport


class TestSlashNextScanReport(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextScanReport class which is using url/scan and OTI API.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextScanReport" with valid set of inputs.')
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
        self.name = 'slashnext-scan-report'
        self.title = 'SlashNext Phishing Incident Response - Scan Report'
        self.description = 'Retrieves the results of a URL scan against a previous scan request. If the scan is ' \
                           'finished, results will be returned immediately; otherwise the message ' \
                           '"check back later" will be returned.'
        self.parameters = [
            {
                'parameter': 'scanid',
                'description': 'Scan ID. Can be retrieved from '
                               'the \"slashnext-url-scan\" action or the \"slashnext-url-scan-sync\" action.'
            },
            {
                'parameter': 'extended_info',
                'description': 'Whether to download forensics data, such as screenshot, HTML, and rendered text. '
                               'If \"true\", forensics data will be returned. If \"false\" (or empty) forensics data '
                               'will not be returned. Default is \"false\".'
            }
        ]
        self.help = '\nACTION: ' + self.name + '\n  ' + self.description + '\n'
        self.help += '\nPARAMETERS: \n'
        for param in self.parameters:
            self.help += '<' + param.get('parameter') + '>\n  ' + param.get('description') + '\n'

        self.api_url_scan = 'https://oti.slashnext.cloud/api/oti/v1/url/scan'
        self.api_data_scan = {
            'authkey': self.api_key,
            'scanid': self.scanid
        }
        self.scan_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "urlData": {
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
            "normalizeData": {
                "normalizeStatus": 0,
                "normalizeMessage": ""
            }
        }

        self.api_url_sc = 'https://oti.slashnext.cloud/api/oti/v1/download/screenshot'
        self.api_data = {
            'authkey': self.api_key,
            'scanid': self.scan_response['urlData'].get('scanId'),
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

        self.state = 'Success'
        self.response_list = [self.scan_response]

        self.response_list_2 = [self.scan_response,
                                self.sc_response,
                                self.html_response,
                                self.text_response]

        self.scan_report_action = SlashNextScanReport(api_key=self.api_key, base_url=self.base_url)

    def test_name(self):
        """
        Test the results of name property of class SlashNextScanReport.
        """
        print(f'{self.test_name.__name__}'
              f': Executing unit test for property "name" of class "SlashNextScanReport".')

        self.assertEqual(self.scan_report_action.name, self.name)

    def test_title(self):
        """
        Test the results of title property of class SlashNextScanReport.
        """
        print(f'{self.test_title.__name__}'
              f': Executing unit test for property "title" of class "SlashNextScanReport".')

        self.assertEqual(self.scan_report_action.title, self.title)

    def test_description(self):
        """
        Test the results of description property of class SlashNextScanReport.
        """
        print(f'{self.test_description.__name__}'
              f': Executing unit test for property "description" of class "SlashNextScanReport".')

        self.assertEqual(self.scan_report_action.description, self.description)

    def test_parameters(self):
        """
        Test the results of parameters property of class SlashNextScanReport.
        """
        print(f'{self.test_parameters.__name__}'
              f': Executing unit test for property "parameters" of class "SlashNextScanReport".')

        self.assertEqual(self.scan_report_action.parameters, self.parameters)

    def test_help(self):
        """
        Test the results of help property of class SlashNextScanReport.
        """
        print(f'{self.test_help.__name__}'
              f': Executing unit test for property "help" of class "SlashNextScanReport".')

        self.assertEqual(self.scan_report_action.help, self.help)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextScanReport.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextScanReport".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.scan_response)

            state, response_list = self.scan_report_action.execution(scanid=self.scanid)

            mocked_request.assert_called_with('POST',
                                              url=self.api_url_scan,
                                              data=self.api_data_scan,
                                              timeout=300)

            self.assertEqual(mocked_request.call_count, 1)

        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list)

        # Second valid case
        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.scan_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            state, response_list = self.scan_report_action.execution(scanid=self.scanid, extended_info='true')

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

            self.assertEqual(mocked_request.call_count, 4)

        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list_2)

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
        print('Finished the execution of tests for class "SlashNextScanReport" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

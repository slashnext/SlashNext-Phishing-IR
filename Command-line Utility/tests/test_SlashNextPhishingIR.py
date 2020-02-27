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
import json
import os
from unittest.mock import patch, Mock
from src.SlashNextPhishingIR import SlashNextPhishingIR


class TestSlashNextPhishingIR(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextPhishingIR class.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextPhishingIR" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        print('\n\nSetting up test pre-conditions with a "valid" API key and a "valid" API base URL.')

        # Set of valid inputs
        self.conf_dir = '.'
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        with open(self.conf_dir + '/snx_conf.json', 'w+') as conf_fd:
            conf_data = dict()
            conf_data['cloud'] = {
                'api_key': self.api_key,
                'base_url': self.base_url
            }
            json.dump(conf_data, conf_fd)

        self.phishing_ir = SlashNextPhishingIR(self.conf_dir)

    def test_set_reset_error(self):
        """
        Test the results of set_error and reset error function of class SlashNextPhishingIR.
        """
        print(f'{self.test_set_reset_error.__name__}'
              f': Executing unit test for function "set_error" and "reset_error" of class "SlashNextPhishingIR".')

        self.phishing_ir.set_error()
        status, details = self.phishing_ir.get_status()

        self.assertEqual(status.lower(), 'error')
        self.assertEqual(details.lower(), 'unknown')

        self.phishing_ir.reset_error()
        status, details = self.phishing_ir.get_status()

        self.assertEqual(status.lower(), 'ok')
        self.assertEqual(details.lower(), 'success')

    def test_load_conf(self):
        """
        Test the results of load_conf function of class SlashNextPhishingIR.
        """
        print(f'{self.test_load_conf.__name__}'
              f': Executing unit test for function "load_conf" of class "SlashNextPhishingIR".')

        self.phishing_ir.load_conf()
        status, details = self.phishing_ir.get_status()

        self.assertEqual(status.lower(), 'ok')
        self.assertEqual(details.lower(), 'success')

    def test_set_conf(self):
        """
        Test the results of set_conf function of class SlashNextPhishingIR.
        """
        print(f'{self.test_set_conf.__name__}'
              f': Executing unit test for function "set_conf" of class "SlashNextPhishingIR".')

        self.phishing_ir.set_conf(api_key=self.api_key, base_url=self.base_url)
        status, details = self.phishing_ir.get_status()

        self.assertEqual(status.lower(), 'ok')
        self.assertEqual(details.lower(), 'success')

    def test_test(self):
        """
        Test the results of test function of class SlashNextPhishingIR.
        """
        print(f'{self.test_test.__name__}'
              f': Executing unit test for function "test" of class "SlashNextPhishingIR".')

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

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            status, details = self.phishing_ir.test()

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(status.lower(), 'ok')
        self.assertEqual(details.lower(), 'success')

    def test_execute(self):
        """
        Test the results of execute function of class SlashNextPhishingIR.
        """
        print(f'{self.test_execute.__name__}'
              f': Executing unit test for function "execute" of class "SlashNextPhishingIR".')

        self.status = 'ok'

        # API quota action
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

        self.title = 'SlashNext Phishing Incident Response - API Quota'
        self.response_list = [self.quota_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            status, details, response_list = self.phishing_ir.execute(f'slashnext-api-quota')

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # Host reputation action
        self.host = 'www.google.com'

        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/host/reputation'
        self.api_data = {
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

        self.title = 'SlashNext Phishing Incident Response - Host Reputation'
        self.response_list = [self.reputation_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.reputation_response)

            status, details, response_list = self.phishing_ir.execute(f'slashnext-host-reputation host={self.host}')

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # Host report action
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

        self.title = 'SlashNext Phishing Incident Response - Host Report'
        self.response_list = [self.reputation_response,
                              self.report_response,
                              self.sc_response,
                              self.html_response,
                              self.text_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.reputation_response),
                Mock(status_code=200, ok=True, json=lambda: self.report_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            status, details, response_list = self.phishing_ir.execute(f'slashnext-host-report host={self.host}')

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

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # Host URLs action
        self.host = 'www.google.com'
        self.limit = 5

        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/host/report'
        self.api_data = {
            'authkey': self.api_key,
            'host': self.host,
            'page': 1,
            'rpp': self.limit
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

        self.title = 'SlashNext Phishing Incident Response - Host URLs'
        self.response_list = [self.urls_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.urls_response)

            status, details, response_list = self.phishing_ir.execute(f'slashnext-host-urls host={self.host} '
                                                                      f'limit={self.limit}')

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # URL scan action
        self.url = 'https://google.com/'

        self.api_url_scan = 'https://oti.slashnext.cloud/api/oti/v1/url/scan'
        self.api_data_scan = {
            'authkey': self.api_key,
            'url': self.url
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

        self.title = 'SlashNext Phishing Incident Response - URL Scan'
        self.response_list = [self.scan_response, self.sc_response, self.html_response, self.text_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.scan_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            status, details, response_list = self.phishing_ir.execute(f'slashnext-url-scan url={self.url} '
                                                                      f'extended_info=true')

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

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # URL scan sync action
        self.url = 'https://google.com/'
        self.timeout = 30

        self.api_url_scan_sync = 'https://oti.slashnext.cloud/api/oti/v1/url/scansync'
        self.api_data_scan_sync = {
            'authkey': self.api_key,
            'url': self.url,
            'timeout': self.timeout
        }
        self.scan_sync_response = {
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
            'scanid': self.scan_sync_response['urlData'].get('scanId'),
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

        self.title = 'SlashNext Phishing Incident Response - URL Scan Sync'
        self.response_list = [self.scan_sync_response, self.sc_response, self.html_response, self.text_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.scan_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            status, details, response_list = self.phishing_ir.execute(f'slashnext-url-scan-sync url={self.url} '
                                                                      f'extended_info=true timeout={self.timeout}')

            mocked_request.assert_any_call('POST',
                                           url=self.api_url_scan_sync,
                                           data=self.api_data_scan_sync,
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

            self.assertEqual(mocked_request.call_count, 4)

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # Scan report action
        self.scanid = 'cc4115b3-2064-4212-a644-871645d94132'

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

        self.title = 'SlashNext Phishing Incident Response - Scan Report'
        self.response_list = [self.scan_response, self.sc_response, self.html_response, self.text_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.side_effect = [
                Mock(status_code=200, ok=True, json=lambda: self.scan_response),
                Mock(status_code=200, ok=True, json=lambda: self.html_response),
                Mock(status_code=200, ok=True, json=lambda: self.text_response),
                Mock(status_code=200, ok=True, json=lambda: self.sc_response)
            ]

            status, details, response_list = self.phishing_ir.execute(f'slashnext-scan-report scanid={self.scanid} '
                                                                      f'extended_info=true')

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

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # Download screenshot action
        self.scanid = 'cc4115b3-2064-4212-a644-871645d94132'

        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/download/screenshot'
        self.api_data = {
            'authkey': self.api_key,
            'scanid': self.scanid,
            'resolution': 'medium'
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

        self.title = 'SlashNext Phishing Incident Response - Download Screenshot'
        self.response_list = [self.screenshot_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.screenshot_response)

            status, details, response_list = self.phishing_ir.execute(f'slashnext-download-screenshot '
                                                                      f'scanid={self.scanid} '
                                                                      f'resolution=medium')

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # Download HTML action
        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/download/html'
        self.api_data = {
            'authkey': self.api_key,
            'scanid': self.scanid,
        }
        self.html_response = {
            "errorNo": 0,
            "errorMsg": "Success",
            "htmlData": {
                "htmlBase64": "test data",
                "htmlName": "Webpage-html",
                "htmlContenType": "html"
            }
        }

        self.title = 'SlashNext Phishing Incident Response - Download HTML'
        self.response_list = [self.html_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.html_response)

            status, details, response_list = self.phishing_ir.execute(f'slashnext-download-html '
                                                                      f'scanid={self.scanid}')

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

        # Download text action
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

        self.title = 'SlashNext Phishing Incident Response - Download Text'
        self.response_list = [self.text_response]

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.text_response)

            status, details, response_list = self.phishing_ir.execute(f'slashnext-download-text '
                                                                      f'scanid={self.scanid}')

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(status.lower(), self.status)
        self.assertEqual(details, self.title)
        self.assertEqual(response_list, self.response_list)

    def tearDown(self):
        """
        This shall be invoked at the end of each test execution contained within this class.
        """
        print('Tearing down test pre-conditions.')

        os.unlink('./snx_conf.json')

    @classmethod
    def tearDownClass(cls):
        """
        This shall be invoked only once at the end of the tests execution contained within this class.
        """
        print('\n\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Finished the execution of tests for class "SlashNextPhishingIR" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

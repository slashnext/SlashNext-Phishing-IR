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
Created on January 14, 2020

@author: Saadat Abid
"""
import unittest
from unittest.mock import patch, Mock
from requests.exceptions import Timeout, RequestException, TooManyRedirects
from src.SlashNextPhishingIR.SlashNextApiQuota import SlashNextApiQuota


class TestSlashNextApiQuotaValid(unittest.TestCase):
    """
    This class implements the positive tests for SlashNextApiQuota class which is using quota/status OTI API.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextApiQuota" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        print('\n\nSetting up test pre-conditions with a "valid" API key and a "valid" API base URL.')

        # Set of valid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of valid expected outputs
        self.name = 'slashnext-api-quota'
        self.title = 'SlashNext Phishing Incident Response - API Quota'
        self.description = 'This action queries the SlashNext cloud database and retrieves the details of API quota.'
        self.parameters = []
        self.help = '\nACTION: ' + self.name + '\n  ' + self.description + '\n'
        self.help += '\nPARAMETERS: None\n'

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

        self.state = 'Success'
        self.response_list = [self.quota_response]

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

    def test_name(self):
        """
        Test the results of name property of class SlashNextApiQuota.
        """
        print(f'{self.test_name.__name__}'
              f': Executing unit test for property "name" of class "SlashNextApiQuota".')

        self.assertEqual(self.api_quota_action.name, self.name)

    def test_title(self):
        """
        Test the results of title property of class SlashNextApiQuota.
        """
        print(f'{self.test_title.__name__}'
              f': Executing unit test for property "title" of class "SlashNextApiQuota".')

        self.assertEqual(self.api_quota_action.title, self.title)

    def test_description(self):
        """
        Test the results of description property of class SlashNextApiQuota.
        """
        print(f'{self.test_description.__name__}'
              f': Executing unit test for property "description" of class "SlashNextApiQuota".')

        self.assertEqual(self.api_quota_action.description, self.description)

    def test_parameters(self):
        """
        Test the results of parameters property of class SlashNextApiQuota.
        """
        print(f'{self.test_parameters.__name__}'
              f': Executing unit test for property "parameters" of class "SlashNextApiQuota".')

        self.assertEqual(self.api_quota_action.parameters, self.parameters)

    def test_help(self):
        """
        Test the results of help property of class SlashNextApiQuota.
        """
        print(f'{self.test_help.__name__}'
              f': Executing unit test for property "help" of class "SlashNextApiQuota".')

        self.assertEqual(self.api_quota_action.help, self.help)

    def test_execution(self):
        """
        Test the results of execution function of class SlashNextApiQuota.
        """
        print(f'{self.test_execution.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota".')

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list)

        # Second valid case
        self.base_url = 'https://oti.slashnext.cloud/api/'
        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        with patch('requests.request', autospec=True, spec_set=True) as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            state, response_list = self.api_quota_action.execution()

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
        print('Finished the execution of tests for class "SlashNextApiQuota" with valid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


class TestSlashNextApiQuotaInvalid(unittest.TestCase):
    """
    This class implements the negative tests for SlashNextApiQuota class which is using quota/status OTI API.
    """

    @classmethod
    def setUpClass(cls):
        """
        This shall be invoked only once at the start of the tests execution contained within this class.
        """
        print('\n─────────────────────────────────────────────────────────────────────────────────────────')
        print('Starting the execution of tests for class "SlashNextApiQuota" with invalid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────')

    def setUp(self):
        """
        This shall be invoked at the start of each test execution contained within this class.
        """
        pass

    def test_execution_invalid_api_key(self):
        """
        Test the results of execution function of class SlashNextApiQuota when an invalid API key is used.
        """
        print('\n\nSetting up test pre-conditions with an "invalid" API key.')

        # Set of invalid inputs
        self.api_key = 'this_is_an_invalid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of invalid expected outputs
        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/quota/status'
        self.api_data = {
            'authkey': self.api_key
        }
        self.quota_response = {
            "errorNo": 7002,
            "errorMsg": "The system is unable to authenticate your request, please provide a valid API key."
        }

        self.state = 'The system is unable to authenticate your request, please provide a valid API key.'
        self.response_list = [self.quota_response]

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_invalid_api_key.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" with invalid API key.')

        with patch('requests.request') as mocked_request:
            mocked_request.return_value = Mock(status_code=200, ok=True, json=lambda: self.quota_response)

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list)

    def test_execution_invalid_base_url(self):
        """
        Test the results of execution function of class SlashNextApiQuota when an invalid base URL is used.
        """
        print('\n\nSetting up test pre-conditions with an "invalid" base URL.')

        # Set of invalid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api/invalid'

        # Set of invalid expected outputs
        self.api_url = 'https://oti.slashnext.cloud/api/invalid/oti/v1/quota/status'
        self.api_data = {
            'authkey': self.api_key
        }
        self.reason = 'Not Found'
        self.status_code = 404
        self.ok = False

        self.state = 'Please provide a valid configuration or contact support@slashnext.com'

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_invalid_base_url.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" with invalid base URL.')

        with patch('requests.request') as mocked_request:
            mocked_request.return_value = Mock(status_code=self.status_code, ok=self.ok, reason=self.reason)

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(state, self.state)
        self.assertEqual(response_list[0].status_code, self.status_code)
        self.assertEqual(response_list[0].ok, self.ok)

    def test_execution_service_down(self):
        """
        Test the results of execution function of class SlashNextApiQuota when HTTP service is down.
        """
        print('\n\nSetting up test pre-conditions with an "invalid" data to induce service down.')

        # Set of invalid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of invalid expected outputs
        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/quota/status'
        self.api_data = {
            'authkey': self.api_key
        }
        self.reason = 'Service Unavailable'
        self.status_code = 503
        self.ok = False

        self.state = 'API response failed due to {}'.format(self.reason)

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_service_down.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" when HTTP service is down.')

        with patch('requests.request') as mocked_request:
            mocked_request.return_value = Mock(status_code=self.status_code, ok=self.ok, reason=self.reason)

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertEqual(state, self.state)
        self.assertEqual(response_list[0].status_code, self.status_code)
        self.assertEqual(response_list[0].ok, self.ok)

    def test_execution_json_exception(self):
        """
        Test the results of execution function of class SlashNextApiQuota when a json decoding exception is raised.
        """
        print('\n\nSetting up test pre-conditions with a json decoding exception.')

        # Set of invalid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of invalid expected outputs
        self.api_url = 'https://oti.slashnext.cloud/api/oti/v1/quota/status'
        self.api_data = {
            'authkey': self.api_key
        }
        self.status_code = 200
        self.ok = True

        self.state = 'API response JSON decoding failed due to '

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_json_exception.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" for json exception.')

        with patch('requests.request') as mocked_request:
            mocked_request.return_value = Mock(status_code=self.status_code, ok=self.ok,
                                               json=lambda: 'Any string instead of dictionary')

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_with('POST',
                                              url=self.api_url,
                                              data=self.api_data,
                                              timeout=300)

        self.assertTrue(state.startswith(self.state))
        self.assertEqual(response_list[0].status_code, self.status_code)
        self.assertEqual(response_list[0].ok, self.ok)

    def test_execution_request_exception(self):
        """
        Test the results of execution function of class SlashNextApiQuota when a request exception is raised.
        """
        print('\n\nSetting up test pre-conditions with a request exception.')

        # Set of invalid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = None

        # Set of invalid expected outputs
        self.state = 'Please provide a valid configuration or contact support@slashnext.com'
        self.response_list = [None]

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_request_exception.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" for request exception.')

        with patch('requests.request') as mocked_request:
            mocked_request.side_effect = RequestException

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_once()

        self.assertRaises(RequestException)
        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list)

    def test_execution_timeout_exception(self):
        """
        Test the results of execution function of class SlashNextApiQuota when a timeout exception is raised.
        """
        print('\n\nSetting up test pre-conditions with a timeout exception.')

        # Set of invalid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of invalid expected outputs
        self.state = 'Looks like the server is taking to long to respond, this can be caused by either poor ' \
                     'connectivity or an error with our servers. Please try again in a while'
        self.response_list = [None]

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_timeout_exception.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" for timeout exception.')

        with patch('requests.request') as mocked_request:
            mocked_request.side_effect = Timeout

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_once()

        self.assertRaises(Timeout)
        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list)

    def test_execution_many_redirects_exception(self):
        """
        Test the results of execution function of class SlashNextApiQuota when a too many redirects exception is raised.
        """
        print('\n\nSetting up test pre-conditions with a too many redirects exception.')

        # Set of invalid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of invalid expected outputs
        self.state = 'Please provide a valid configuration or contact support@slashnext.com'
        self.response_list = [None]

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_many_redirects_exception.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" for too many redirects exception.')

        with patch('requests.request') as mocked_request:
            mocked_request.side_effect = TooManyRedirects

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_once()

        self.assertRaises(TooManyRedirects)
        self.assertEqual(state, self.state)
        self.assertEqual(response_list, self.response_list)

    def test_execution_catchall_exception(self):
        """
        Test the results of execution function of class SlashNextApiQuota when a catch all exception is raised.
        """
        print('\n\nSetting up test pre-conditions with a catch-all exception.')

        # Set of invalid inputs
        self.api_key = 'this_is_a_valid_api_key'
        self.base_url = 'https://oti.slashnext.cloud/api'

        # Set of invalid expected outputs
        self.reason = 'Whatever reason'
        self.state = 'API response failed due to {}'.format(self.reason)
        self.response_list = [None]

        self.api_quota_action = SlashNextApiQuota(api_key=self.api_key, base_url=self.base_url)

        print(f'{self.test_execution_catchall_exception.__name__}'
              f': Executing unit test for function "execution" of class "SlashNextApiQuota" for catch-all exception.')

        with patch('requests.request') as mocked_request:
            mocked_request.side_effect = Exception(self.reason)

            state, response_list = self.api_quota_action.execution()

            mocked_request.assert_called_once()

        self.assertRaises(RequestException)
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
        print('Finished the execution of tests for class "SlashNextApiQuota" with invalid set of inputs.')
        print('─────────────────────────────────────────────────────────────────────────────────────────\n')


if __name__ == '__main__':
    unittest.main()

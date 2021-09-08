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
Created on December 10, 2019

@author: Saadat Abid
"""
from os import path, makedirs
import json
from .SlashNextApiQuota import SlashNextApiQuota
from .SlashNextHostReputation import SlashNextHostReputation
from .SlashNextHostReport import SlashNextHostReport
from .SlashNextHostUrls import SlashNextHostUrls
from .SlashNextUrlReputation import SlashNextUrlReputation
from .SlashNextUrlScan import SlashNextUrlScan
from .SlashNextUrlScanSync import SlashNextUrlScanSync
from .SlashNextScanReport import SlashNextScanReport
from .SlashNextDownloadScreenshot import SlashNextDownloadScreenshot
from .SlashNextDownloadHtml import SlashNextDownloadHtml
from .SlashNextDownloadText import SlashNextDownloadText


class SlashNextPhishingIR(object):
    """
    This class implements the SlashNext Phishing Incident Response back-end using the SlashNext OTI APIs.

    Attributes:
        conf_dir (str): The absolute path of the directory where OTI configuration file 'snx_conf.json' is placed.
    """
    def __init__(self, conf_dir):
        """
        The constructor for SlashNextPhishingIR class.

        :param conf_dir: The absolute path of the directory where OTI configuration file 'snx_conf.json' is placed.
        """
        self.__conf_dir = conf_dir
        self.__status = 'ok'
        self.__details = 'Success'

        self.api_key = ''
        self.base_url = 'https://oti.slashnext.cloud/api'

        self.__api_quota = None
        self.__host_reputation = None
        self.__host_report = None
        self.__host_urls = None
        self.__url_reputation = None
        self.__url_scan = None
        self.__url_scan_sync = None
        self.__scan_report = None
        self.__download_sc = None
        self.__download_html = None
        self.__download_text = None

        self.load_conf()

        self.__supported_actions = self.get_action_list()

    def load_conf(self):
        """
        Loads the OTI configurations from the default location and updates the status accordingly.
        """
        try:
            with open(self.__conf_dir + '/snx_conf.json', 'r+') as conf_fd:
                conf_data = conf_fd.read()

            json_conf = json.loads(conf_data)
            if json_conf.get('cloud'):
                api_key = json_conf.get('cloud').get('api_key')
                base_url = json_conf.get('cloud').get('base_url')

                if api_key is None and base_url is None:
                    self.set_error('Please provide a valid configuration or contact support@slashnext.com')
                elif api_key is None or api_key.strip() == '':
                    self.set_error('Please provide a valid API Key or contact support@slashnext.com')
                elif base_url is None:
                    self.api_key = api_key
                else:
                    self.api_key = api_key
                    self.base_url = base_url
            else:
                self.set_error('Please provide a valid configuration or contact support@slashnext.com')

        except PermissionError:
            self.set_error('Permission denied, please acquire the proper privileges and retry')
        except Exception as e:
            self.set_error('Please provide a valid configuration or contact support@slashnext.com')

        self.__api_quota = SlashNextApiQuota(self.api_key, self.base_url)
        self.__host_reputation = SlashNextHostReputation(self.api_key, self.base_url)
        self.__host_report = SlashNextHostReport(self.api_key, self.base_url)
        self.__host_urls = SlashNextHostUrls(self.api_key, self.base_url)
        self.__url_reputation = SlashNextUrlReputation(self.api_key, self.base_url)
        self.__url_scan = SlashNextUrlScan(self.api_key, self.base_url)
        self.__url_scan_sync = SlashNextUrlScanSync(self.api_key, self.base_url)
        self.__scan_report = SlashNextScanReport(self.api_key, self.base_url)
        self.__download_sc = SlashNextDownloadScreenshot(self.api_key, self.base_url)
        self.__download_html = SlashNextDownloadHtml(self.api_key, self.base_url)
        self.__download_text = SlashNextDownloadText(self.api_key, self.base_url)

    def set_conf(self, api_key, base_url):
        """
        Saves the new OTI configurations on the default location.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        try:
            if not path.exists(self.__conf_dir):
                makedirs(self.__conf_dir)

            with open(self.__conf_dir + '/snx_conf.json', 'w+') as conf_fd:
                conf_data = dict()
                conf_data['cloud'] = {
                    'api_key': api_key,
                    'base_url': base_url
                }
                json.dump(conf_data, conf_fd)

            self.reset_error()
            self.load_conf()

        except PermissionError:
            self.set_error('Permission denied, please acquire the proper privileges and retry')
        except Exception as e:
            self.set_error('Please provide a valid configuration or contact support@slashnext.com')

    def set_error(self, details='Unknown'):
        """
        Sets the status to 'error'.

        :param details: The details of the 'error' condition.
        """
        self.__status = 'error'
        self.__details = details

    def reset_error(self):
        """
        Resets the status to 'ok'.
        """
        self.__status = 'ok'
        self.__details = 'Success'

    def get_status(self):
        """
        Gets the current status.

        :return: The current status and the details of the status.
        """
        return self.__status, self.__details

    def get_action_list(self):
        """
        Gets the list of supported actions.

        :return: List of supported actions.
        """
        action_list = list()

        action_list.append(self.__api_quota.name)
        action_list.append(self.__host_reputation.name)
        action_list.append(self.__host_report.name)
        action_list.append(self.__host_urls.name)
        action_list.append(self.__url_reputation.name)
        action_list.append(self.__url_scan.name)
        action_list.append(self.__url_scan_sync.name)
        action_list.append(self.__scan_report.name)
        action_list.append(self.__download_sc.name)
        action_list.append(self.__download_html.name)
        action_list.append(self.__download_text.name)

        return action_list

    def get_action_help(self, action='all'):
        """
        Gets the help on the desired action.

        :param action: Action name on which help is desired
        :return: Help on the requested action.
        """
        action_lower = action.lower()

        if action_lower == 'slashnext-api-quota':
            return self.__api_quota.help
        elif action_lower == 'slashnext-host-reputation':
            return self.__host_reputation.help
        elif action_lower == 'slashnext-host-report':
            return self.__host_report.help
        elif action_lower == 'slashnext-host-urls':
            return self.__host_urls.help
        elif action_lower == 'slashnext-url-reputation':
            return self.__url_reputation.help
        elif action_lower == 'slashnext-url-scan':
            return self.__url_scan.help
        elif action_lower == 'slashnext-url-scan-sync':
            return self.__url_scan_sync.help
        elif action_lower == 'slashnext-scan-report':
            return self.__scan_report.help
        elif action_lower == 'slashnext-download-screenshot':
            return self.__download_sc.help
        elif action_lower == 'slashnext-download-html':
            return self.__download_html.help
        elif action_lower == 'slashnext-download-text':
            return self.__download_text.help
        else:
            action_list = self.get_action_list()
            help_str = ''
            for each_action in action_list:
                help_str += self.get_action_help(each_action)

            return help_str

    def test(self):
        """
        Performs the connectivity and authentication test with SlashNext OTI cloud.

        :return: The current status and the details of the status after connectivity and authentication test.
        """
        details, response = self.__api_quota.execution()
        if details != 'Success':
            self.set_error(details)
        else:
            self.reset_error()

        return self.__status, self.__details

    def __execute_api_quota(self, action_str_list):
        """
        Execute the API Quota action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) != 1:
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__api_quota.parameters
        else:
            details, response_list = self.__api_quota.execution()

            if details.lower() == 'success':
                return 'ok', self.__api_quota.title, response_list
            else:
                return 'error', details, response_list

    def __execute_host_reputation(self, action_str_list):
        """
        Execute the Host Reputation action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) != 2 or action_str_list[1].startswith('host=') is False:
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__host_reputation.parameters
        else:
            details, response_list = self.__host_reputation.execution(host=action_str_list[1][5:])

            if details.lower() == 'success':
                return 'ok', self.__host_reputation.title, response_list
            else:
                return 'error', details, response_list

    def __execute_host_report(self, action_str_list):
        """
        Execute the Host Report action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) != 2 or action_str_list[1].startswith('host=') is False:
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__host_report.parameters
        else:
            details, response_list = self.__host_report.execution(host=action_str_list[1][5:])

            if details.lower() == 'success':
                return 'ok', self.__host_report.title, response_list
            else:
                return 'error', details, response_list

    def __execute_host_urls(self, action_str_list):
        """
        Execute the Host URLs action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) < 2 or len(action_str_list) > 3 or \
                action_str_list[1].startswith('host=') is False or \
                (len(action_str_list) == 3 and action_str_list[2].startswith('limit=') is False):
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__host_urls.parameters
        else:
            if len(action_str_list) == 3:
                details, response_list = self.__host_urls.execution(host=action_str_list[1][5:],
                                                                    limit=int(action_str_list[2][6:]))
            else:
                details, response_list = self.__host_urls.execution(host=action_str_list[1][5:])

            if details.lower() == 'success':
                return 'ok', self.__host_urls.title, response_list
            else:
                return 'error', details, response_list

    def __execute_url_scan(self, action_str_list):
        """
        Execute the URL Scan action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) < 2 or len(action_str_list) > 3 or \
                action_str_list[1].startswith('url=') is False or \
                (len(action_str_list) == 3 and action_str_list[2].startswith('extended_info=') is False):
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__url_scan.parameters
        else:
            if len(action_str_list) == 3:
                details, response_list = self.__url_scan.execution(url=action_str_list[1][4:],
                                                                   extended_info=action_str_list[2][14:])
            else:
                details, response_list = self.__url_scan.execution(url=action_str_list[1][4:])

            if details.lower() == 'success':
                return 'ok', self.__url_scan.title, response_list
            else:
                return 'error', details, response_list

    def __execute_url_reputation(self, action_str_list):
        """
        Execute the URL Reputation action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) != 2 or action_str_list[1].startswith('url=') is False:
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__url_reputation.parameters
        else:
            details, response_list = self.__url_reputation.execution(url=action_str_list[1][4:])

            if details.lower() == 'success':
                return 'ok', self.__url_reputation.title, response_list
            else:
                return 'error', details, response_list

    def __execute_url_scan_sync(self, action_str_list):
        """
        Execute the URL Scan Sync action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) < 2 or len(action_str_list) > 4 or action_str_list[1].startswith('url=') is False or \
                (len(action_str_list) == 3 and
                 (action_str_list[2].startswith('extended_info=') is False and
                  action_str_list[2].startswith('timeout=') is False)) or \
                (len(action_str_list) == 4 and
                 action_str_list[2].startswith('extended_info=') is True and
                 action_str_list[3].startswith('timeout=') is False) or \
                (len(action_str_list) == 4 and
                 action_str_list[2].startswith('timeout=') is True and
                 action_str_list[3].startswith('extended_info=') is False):
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__url_scan_sync.parameters
        else:
            if len(action_str_list) == 4 and action_str_list[2].startswith('extended_info=') is True:
                details, response_list = self.__url_scan_sync.execution(url=action_str_list[1][4:],
                                                                        extended_info=action_str_list[2][14:],
                                                                        timeout=int(action_str_list[3][8:]))
            elif len(action_str_list) == 4 and action_str_list[2].startswith('extended_info=') is False:
                details, response_list = self.__url_scan_sync.execution(url=action_str_list[1][4:],
                                                                        extended_info=action_str_list[3][14:],
                                                                        timeout=int(action_str_list[2][8:]))
            elif len(action_str_list) == 3 and action_str_list[2].startswith('extended_info=') is True:
                details, response_list = self.__url_scan_sync.execution(url=action_str_list[1][4:],
                                                                        extended_info=action_str_list[2][14:])
            elif len(action_str_list) == 3 and action_str_list[2].startswith('extended_info=') is False:
                details, response_list = self.__url_scan_sync.execution(url=action_str_list[1][4:],
                                                                        timeout=int(action_str_list[2][8:]))
            else:
                details, response_list = self.__url_scan_sync.execution(url=action_str_list[1][4:])

            if details.lower() == 'success':
                return 'ok', self.__url_scan_sync.title, response_list
            else:
                return 'error', details, response_list

    def __execute_scan_report(self, action_str_list):
        """
        Execute the Scan Report action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) < 2 or len(action_str_list) > 3 or \
                action_str_list[1].startswith('scanid=') is False or \
                (len(action_str_list) == 3 and action_str_list[2].startswith('extended_info=') is False):
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__scan_report.parameters
        else:
            if len(action_str_list) == 3:
                details, response_list = self.__scan_report.execution(scanid=action_str_list[1][7:],
                                                                      extended_info=action_str_list[2][14:])
            else:
                details, response_list = self.__scan_report.execution(scanid=action_str_list[1][7:])

            if details.lower() == 'success':
                return 'ok', self.__scan_report.title, response_list
            else:
                return 'error', details, response_list

    def __execute_download_screenshot(self, action_str_list):
        """
        Execute the Download Screenshot action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) < 2 or len(action_str_list) > 3 or \
                action_str_list[1].startswith('scanid=') is False or \
                (len(action_str_list) == 3 and action_str_list[2].startswith('resolution=') is False):
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__download_sc.parameters
        else:
            if len(action_str_list) == 3:
                details, response_list = self.__download_sc.execution(scanid=action_str_list[1][7:],
                                                                      resolution=action_str_list[2][11:])
            else:
                details, response_list = self.__download_sc.execution(scanid=action_str_list[1][7:])

            if details.lower() == 'success':
                return 'ok', self.__download_sc.title, response_list
            else:
                return 'error', details, response_list

    def __execute_download_html(self, action_str_list):
        """
        Execute the Download HTML action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) != 2 or action_str_list[1].startswith('scanid=') is False:
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__download_html.parameters
        else:
            details, response_list = self.__download_html.execution(scanid=action_str_list[1][7:])

            if details.lower() == 'success':
                return 'ok', self.__download_html.title, response_list
            else:
                return 'error', details, response_list

    def __execute_download_text(self, action_str_list):
        """
        Execute the Download Text action with the given parameters after validating the input 'action_str_list'.

        :param action_str_list: List of action string components.
        :return: Status of action execution and list of SlashNext API response(s).
        """
        if len(action_str_list) != 2 or action_str_list[1].startswith('scanid=') is False:
            return 'error', 'Invalid Request! Please verify request parameters and try again', \
                   self.__download_text.parameters
        else:
            details, response_list = self.__download_text.execution(scanid=action_str_list[1][7:])

            if details.lower() == 'success':
                return 'ok', self.__download_text.title, response_list
            else:
                return 'error', details, response_list

    def execute(self, action_str):
        """
        Execute the requested action with the given parameters after parsing the input 'action_str'.

        :param action_str: Action and parameter(s) as a string using ' ' as a separator. i.e. valid format
        <action-name> <required-parameter> <optional-parameter-1> <optional-parameter-2> ...
        :return: Status of action execution and list of SlashNext API response(s).
        """
        action_str_list = action_str.strip().split()
        action = action_str_list[0].strip()
        if action in self.__supported_actions:
            if action == 'slashnext-api-quota':
                return self.__execute_api_quota(action_str_list)

            elif action == 'slashnext-host-reputation':
                return self.__execute_host_reputation(action_str_list)

            elif action == 'slashnext-host-report':
                return self.__execute_host_report(action_str_list)

            elif action == 'slashnext-host-urls':
                return self.__execute_host_urls(action_str_list)

            elif action == 'slashnext-url-reputation':
                return self.__execute_url_reputation(action_str_list)

            elif action == 'slashnext-url-scan':
                return self.__execute_url_scan(action_str_list)

            elif action == 'slashnext-url-scan-sync':
                return self.__execute_url_scan_sync(action_str_list)

            elif action == 'slashnext-scan-report':
                return self.__execute_scan_report(action_str_list)

            elif action == 'slashnext-download-screenshot':
                return self.__execute_download_screenshot(action_str_list)

            elif action == 'slashnext-download-html':
                return self.__execute_download_html(action_str_list)

            elif action == 'slashnext-download-text':
                return self.__execute_download_text(action_str_list)
        else:
            return 'error', 'Invalid action', self.__supported_actions

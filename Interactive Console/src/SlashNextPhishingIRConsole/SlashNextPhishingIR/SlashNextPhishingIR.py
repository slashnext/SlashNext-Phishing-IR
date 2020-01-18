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
from os import path
import json
from .SlashNextApiQuota import SlashNextApiQuota
from .SlashNextHostReputation import SlashNextHostReputation
from .SlashNextHostReport import SlashNextHostReport
from .SlashNextHostUrls import SlashNextHostUrls
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
        self.conf_dir = conf_dir
        self.status = 'ok'
        self.details = 'Success'

        self.api_key = None
        self.base_url = None

        self.api_quota = None
        self.host_reputation = None
        self.host_report = None
        self.host_urls = None
        self.url_scan = None
        self.url_scan_sync = None
        self.scan_report = None
        self.download_sc = None
        self.download_html = None
        self.download_text = None

        self.load_conf()

        self.supported_actions = self.get_action_list()

    def load_conf(self):
        """
        Loads the OTI configurations from the default location and updates the status accordingly.
        """
        if path.isfile(self.conf_dir + '/snx_conf.json'):
            try:
                conf_fd = open(self.conf_dir + '/snx_conf.json', 'r+')
                conf_data = conf_fd.read()
                if conf_data == '':
                    self.set_error('Please provide a valid configuration or contact support@slashnext.com')
                else:
                    try:
                        json_conf = json.loads(conf_data)
                        if json_conf.get('cloud'):
                            self.api_key = json_conf.get('cloud').get('api_key')
                            self.base_url = json_conf.get('cloud').get('base_url')

                            if self.api_key is None:
                                self.set_error('Please provide a valid API Key or contact support@slashnext.com')
                            if self.base_url is None:
                                self.set_error('Please provide a valid API Key or contact support@slashnext.com')
                        else:
                            self.set_error('Please provide a valid configuration or contact support@slashnext.com')
                    except Exception as e:
                        self.set_error('Please provide a valid configuration or contact support@slashnext.com')
            except Exception as e:
                self.set_error('Permission denied, please run the console with proper privileges')
        else:
            self.set_error('Please provide a valid configuration or contact support@slashnext.com')

        self.api_quota = SlashNextApiQuota(self.api_key, self.base_url)
        self.host_reputation = SlashNextHostReputation(self.api_key, self.base_url)
        self.host_report = SlashNextHostReport(self.api_key, self.base_url)
        self.host_urls = SlashNextHostUrls(self.api_key, self.base_url)
        self.url_scan = SlashNextUrlScan(self.api_key, self.base_url)
        self.url_scan_sync = SlashNextUrlScanSync(self.api_key, self.base_url)
        self.scan_report = SlashNextScanReport(self.api_key, self.base_url)
        self.download_sc = SlashNextDownloadScreenshot(self.api_key, self.base_url)
        self.download_html = SlashNextDownloadHtml(self.api_key, self.base_url)
        self.download_text = SlashNextDownloadText(self.api_key, self.base_url)

    def set_conf(self, api_key, base_url):
        """
        Saves the new OTI configurations on the default location.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        try:
            conf_fd = open(self.conf_dir + '/snx_conf.json', 'w+')
            conf_data = dict()
            conf_data['cloud'] = {
                'api_key': api_key,
                'base_url': base_url
            }
            json.dump(conf_data, conf_fd)

            self.api_key = api_key
            self.base_url = base_url
        except Exception as e:
            self.set_error('Permission denied, please run the console with proper privileges')

    def set_error(self, details='Unknown'):
        """
        Sets the status to 'error'.

        :param details: The details of the 'error' condition.
        """
        self.status = 'error'
        self.details = details

    def reset_error(self):
        """
        Resets the status to 'ok'.
        """
        self.status = 'ok'
        self.details = 'Success'

    def get_status(self):
        """
        Gets the current status.

        :return: The current status and the details of the status.
        """
        return self.status, self.details

    def get_action_list(self):
        """
        Gets the list of supported actions.

        :return: List of supported actions.
        """
        action_list = list()

        action_list.append(self.api_quota.name())
        action_list.append(self.host_reputation.name())
        action_list.append(self.host_report.name())
        action_list.append(self.host_urls.name())
        action_list.append(self.url_scan.name())
        action_list.append(self.url_scan_sync.name())
        action_list.append(self.scan_report.name())
        action_list.append(self.download_sc.name())
        action_list.append(self.download_html.name())
        action_list.append(self.download_text.name())

        return action_list

    def get_action_help(self, action='all'):
        """
        Gets the help on the desired action.

        :param action: Action name on which help is desired
        :return: Help on the requested action.
        """
        action_lower = action.lower()

        if action_lower == 'slashnext-api-quota':
            return self.api_quota.help()
        elif action_lower == 'slashnext-host-reputation':
            return self.host_reputation.help()
        elif action_lower == 'slashnext-host-report':
            return self.host_report.help()
        elif action_lower == 'slashnext-host-urls':
            return self.host_urls.help()
        elif action_lower == 'slashnext-url-scan':
            return self.url_scan.help()
        elif action_lower == 'slashnext-url-scan-sync':
            return self.url_scan_sync.help()
        elif action_lower == 'slashnext-scan-report':
            return self.scan_report.help()
        elif action_lower == 'slashnext-download-screenshot':
            return self.download_sc.help()
        elif action_lower == 'slashnext-download-html':
            return self.download_html.help()
        elif action_lower == 'slashnext-download-text':
            return self.download_text.help()
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
        details, response = self.api_quota.execution()
        if details != 'Success':
            self.set_error(details)
        else:
            self.reset_error()

        return self.status, self.details

    def execute(self, action_str):
        """
        Execute the requested action with the given parameters after parsing the input 'action_str'.

        :param action_str: Action and parameter(s) as a string using ' ' as a separator. i.e. valid format
        <action-name> <required-parameter> <optional-parameter-1> <optional-parameter-2> ...
        :return: Status of action execution and list of SlashNext API response(s).
        """
        response_list = []
        action_str_list = action_str.strip().split()
        action = action_str_list[0].strip()
        if action in self.supported_actions:
            if action == 'slashnext-api-quota':
                if len(action_str_list) != 1:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.api_quota.parameters()
                else:
                    details, response_list = self.api_quota.execution()

                    if details.lower() == 'success':
                        return 'ok', self.api_quota.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-host-reputation':
                if len(action_str_list) != 2:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.host_reputation.parameters()
                elif action_str_list[1].startswith('host=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.host_reputation.parameters()
                else:
                    details, response_list = self.host_reputation.execution(
                        host=action_str_list[1][5:])

                    if details.lower() == 'success':
                        return 'ok', self.host_reputation.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-host-report':
                if len(action_str_list) != 2:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.host_report.parameters()
                elif action_str_list[1].startswith('host=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.host_report.parameters()
                else:
                    details, response_list = self.host_report.execution(
                        host=action_str_list[1][5:])

                    if details.lower() == 'success':
                        return 'ok', self.host_report.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-host-urls':
                if len(action_str_list) < 2 or len(action_str_list) > 3:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.host_urls.parameters()
                elif action_str_list[1].startswith('host=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.host_urls.parameters()
                elif len(action_str_list) == 3 and action_str_list[2].startswith('limit=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.host_urls.parameters()
                else:
                    if len(action_str_list) == 3:
                        details, response_list = self.host_urls.execution(
                            host=action_str_list[1][5:],
                            limit=action_str_list[2][6:])
                    else:
                        details, response_list = self.host_urls.execution(
                            host=action_str_list[1][5:])

                    if details.lower() == 'success':
                        return 'ok', self.host_urls.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-url-scan':
                if len(action_str_list) < 2 or len(action_str_list) > 3:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan.parameters()
                elif action_str_list[1].startswith('url=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan.parameters()
                elif len(action_str_list) == 3 and action_str_list[2].startswith('extended_info=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan.parameters()
                else:
                    if len(action_str_list) == 3:
                        details, response_list = self.url_scan.execution(
                            url=action_str_list[1][4:],
                            extended_info=action_str_list[2][14:])
                    else:
                        details, response_list = self.url_scan.execution(
                            url=action_str_list[1][4:])

                    if details.lower() == 'success':
                        return 'ok', self.url_scan.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-url-scan-sync':
                if len(action_str_list) < 2 or len(action_str_list) > 4:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan_sync.parameters()
                elif action_str_list[1].startswith('url=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan_sync.parameters()
                elif len(action_str_list) == 3 \
                        and (action_str_list[2].startswith('extended_info=') is False
                             and action_str_list[2].startswith('timeout=') is False):
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan_sync.parameters()
                elif len(action_str_list) == 4 and action_str_list[2].startswith('extended_info=') is True \
                        and action_str_list[3].startswith('timeout=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan_sync.parameters()
                elif len(action_str_list) == 4 and action_str_list[2].startswith('timeout=') is True \
                        and action_str_list[3].startswith('extended_info=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.url_scan_sync.parameters()
                else:
                    if len(action_str_list) == 4:
                        if action_str_list[2].startswith('extended_info=') is True:
                            details, response_list = self.url_scan_sync.execution(
                                url=action_str_list[1][4:],
                                extended_info=action_str_list[2][14:],
                                timeout=action_str_list[3][8:])
                        else:
                            details, response_list = self.url_scan_sync.execution(
                                url=action_str_list[1][4:],
                                extended_info=action_str_list[3][14:],
                                timeout=action_str_list[2][8:])
                    elif len(action_str_list) == 3:
                        if action_str_list[2].startswith('extended_info=') is True:
                            details, response_list = self.url_scan_sync.execution(
                                url=action_str_list[1][4:],
                                extended_info=action_str_list[2][14:])
                        else:
                            details, response_list = self.url_scan_sync.execution(
                                url=action_str_list[1][4:],
                                timeout=action_str_list[2][8:])
                    else:
                        details, response_list = self.url_scan_sync.execution(
                            url=action_str_list[1][4:])

                    if details.lower() == 'success':
                        return 'ok', self.url_scan_sync.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-scan-report':
                if len(action_str_list) < 2 or len(action_str_list) > 3:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.scan_report.parameters()
                elif action_str_list[1].startswith('scanid=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.scan_report.parameters()
                elif len(action_str_list) == 3 and action_str_list[2].startswith('extended_info=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.scan_report.parameters()
                else:
                    if len(action_str_list) == 3:
                        details, response_list = self.scan_report.execution(
                            scanid=action_str_list[1][7:],
                            extended_info=action_str_list[2][14:])
                    else:
                        details, response_list = self.scan_report.execution(
                            scanid=action_str_list[1][7:])

                    if details.lower() == 'success':
                        return 'ok', self.scan_report.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-download-screenshot':
                if len(action_str_list) < 2 or len(action_str_list) > 3:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.download_sc.parameters()
                elif action_str_list[1].startswith('scanid=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.download_sc.parameters()
                elif len(action_str_list) == 3 and action_str_list[2].startswith('resolution=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.download_sc.parameters()
                else:
                    if len(action_str_list) == 3:
                        details, response_list = self.download_sc.execution(
                            scanid=action_str_list[1][7:],
                            resolution=action_str_list[2][11:])
                    else:
                        details, response_list = self.download_sc.execution(
                            scanid=action_str_list[1][7:])

                    if details.lower() == 'success':
                        return 'ok', self.download_sc.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-download-html':
                if len(action_str_list) != 2:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.download_html.parameters()
                elif action_str_list[1].startswith('scanid=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.download_html.parameters()
                else:
                    details, response_list = self.download_html.execution(
                        scanid=action_str_list[1][7:])

                    if details.lower() == 'success':
                        return 'ok', self.download_html.title(), response_list
                    else:
                        return 'error', details, response_list

            elif action == 'slashnext-download-text':
                if len(action_str_list) != 2:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.download_text.parameters()
                elif action_str_list[1].startswith('scanid=') is False:
                    return 'error', 'Invalid Request! Please verify request parameters and try again', \
                           self.download_text.parameters()
                else:
                    details, response_list = self.download_text.execution(
                        scanid=action_str_list[1][7:])

                    if details.lower() == 'success':
                        return 'ok', self.download_text.title(), response_list
                    else:
                        return 'error', details, response_list

        else:
            return 'error', 'Invalid action', self.supported_actions

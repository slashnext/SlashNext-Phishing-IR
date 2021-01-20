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
Created on January 15, 2021

@author: Saadat Abid
"""

import os
import json
import time
import sys
import urllib.parse as urlparse
import regex as re
from urllib.parse import unquote
from w3lib import url as w3url
from datetime import datetime
from .SlashNextAction import SlashNextAction
from .SlashNextAPIs import snx_api_request, URL_SCAN_API, HOST_REPUTE_API, DL_SC_API, DL_HTML_API, DL_TEXT_API

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'
SUPPORTED_PROTO = ('http://', 'https://')
INVALID_EMAIL_TLD = ('.exe', '.php', '.html')
DUMMY_EMAIL = 'Jackdavis@eureliosollutions.com'


class SlashNextUrlScanBulk(SlashNextAction):
    """
    This class implements the 'slashnext-url-scan-bulk' action by using the 'url/scan', 'download/screenshot',
    'download/html', and 'download/text' SlashNext OTI API.

    Attributes:
        api_key (str): The API Key used to authenticate with SlashNext OTI cloud.
        base_url (str): The Base URL for accessing SlashNext OTI APIs.
    """
    def __init__(self, api_key, base_url):
        """
        The constructor for SlashNextUrlScanBulk class.

        :param api_key: The API Key used to authenticate with SlashNext OTI cloud.
        :param base_url: The Base URL for accessing SlashNext OTI APIs.
        """
        self.__name = 'slashnext-url-scan-bulk'
        self.__title = 'SlashNext Phishing Incident Response - URL Scan Bulk'
        self.__description = 'Performs bulk URL scan with the SlashNext cloud-based SEER Engine. ' \
                             'The scan results are returned immediately if a URL already exists in the cache. ' \
                             'For unknown URLs, a scan request will be sent, and the command will poll periodically ' \
                             'to check the scan status and return results immediately when they become available.'
        self.__parameters = [
            {
                'parameter': 'input',
                'description': 'Input file path containing line separated valid URLs.'
            },
            {
                'parameter': 'output',
                'description': 'Output directory path where scan logs will be stored.'
            },
            {
                'parameter': 'poll_interval',
                'description': 'Time interval after which pending scan status is checked, value is in seconds. '
                               'If no poll_interval value is specified, the default value is 60 seconds.'
            },
            {
                'parameter': 'retries',
                'description': 'Total number of times, the scan status is checked for pending scans. '
                               'If no retries value is specified, the default value is 10.'
            },
            # {and webpage forensics
            #     'parameter': 'extended_info',
            #     'description': 'Whether to download forensics data, such as screenshot, HTML, and rendered text. '
            #                    'If \"true\", forensics data will be returned. If \"false\" (or empty) forensics '
            #                    'data will not be returned. Default is \"false\".'
            # }
        ]

        super().__init__(name=self.__name,
                         title=self.__title,
                         description=self.__description,
                         parameters=self.__parameters)

        self.__api_key = api_key
        self.__base_url = base_url
        self.__url_regex = self._get_url_validator()
        self.__email_regex = re.compile(r'([\w.+-]+\@[a-z\d\-]+\.[a-z\d\-.]+[a-z\d])', re.IGNORECASE)

    def execution(self, input_path, output_path='.', extended_info='false', poll_interval=60, retries=10):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :param input_path: Input file path which contains line separated valid URLs.
        :param output_path: Output directory path where webpage forensic data will be placed.
        :param extended_info: Whether to download forensics data, such as screenshot, HTML, and rendered text.
        :param poll_interval: A poll interval value in seconds. If no value is specified, a default wait is 60 seconds.
        :param retries: A total number of times scan status is polled if previous status was pending. Default is 10.
        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        urls_response = []
        try:
            if os.path.isdir(output_path):
                utc_datetime = datetime.utcnow()
                timestamp = utc_datetime.strftime("%Y%m%d_%H%M%S")
                output_path = output_path if output_path.endswith('/') else output_path + '/'
                output_path = output_path + timestamp + '/'
                os.makedirs(output_path, exist_ok=True)

                if os.path.isfile(input_path) and os.stat(input_path).st_size:
                    compiled_results = {
                        "input": input_path,
                        "output": output_path
                    }
                    urls_response.append(compiled_results)

                    urls_original = 0
                    urls_found_in_cache = 0
                    urls_found_invalid = 0
                    urls_found_malicious = 0
                    urls_found_benign = 0
                    urls_scan_error = 0
                    urls_submitted_for_scan = 0
                    state = ''

                    with open(input_path, 'r') as submitted_file:
                        for url in submitted_file:
                            if url.rstrip():
                                if urls_original == 0:
                                    sys.stdout.write('------------------------------------------------------------\n')
                                    self._move_curser(lines=10, direction='down')

                                urls_original = urls_original + 1
                                with open(output_path+'urls_original.txt', 'a+') as fp:
                                    fp.writelines(url)

                                api_data = {
                                    'url': url,
                                    'authkey': self.__api_key
                                }
                                state, response = snx_api_request(self.__base_url, URL_SCAN_API, api_data)

                                if response and isinstance(response, dict):
                                    if response.get('errorNo') == 0:
                                        urls_found_in_cache = urls_found_in_cache + 1
                                        with open(output_path + 'urls_found_in_cache.txt', 'a+') as fp:
                                            fp.writelines(url)

                                        url_data = response.get('urlData')
                                        threat_data = url_data.get('landingUrl').get('threatData') if 'landingUrl' in url_data else url_data.get('threatData')
                                        if threat_data.get('verdict') == 'Malicious':
                                            urls_found_malicious = urls_found_malicious + 1
                                            with open(output_path + 'urls_found_malicious.txt', 'a+') as fp:
                                                fp.writelines(url)
                                            with open(output_path + 'malicious_urls_raw.log', 'a+') as fp:
                                                fp.writelines(json.dumps(response) + '\n')
                                                urls_response.append(response)
                                        else:
                                            host = self.split_host_uri(self.normalize_url(url))[1]
                                            data = {
                                                'host': host,
                                                'authkey': self.__api_key
                                            }
                                            h_s, h_r = snx_api_request(self.__base_url, HOST_REPUTE_API, data)

                                            if h_r.get('errorNo', 404) == 0:
                                                host_threat_data = h_r.get('threatData')
                                                if host_threat_data.get('verdict') == 'Malicious':
                                                    response['urlData']['threatData'] = host_threat_data

                                                    urls_found_malicious = urls_found_malicious + 1
                                                    with open(output_path + 'urls_found_malicious.txt', 'a+') as fp:
                                                        fp.writelines(url)
                                                    with open(output_path + 'malicious_urls_raw.log', 'a+') as fp:
                                                        fp.writelines(json.dumps(response) + '\n')
                                                        urls_response.append(response)
                                                else:
                                                    urls_found_benign = urls_found_benign + 1
                                                    with open(output_path + 'urls_found_benign.txt', 'a+') as fp:
                                                        fp.writelines(url)
                                                    with open(output_path + 'benign_urls_raw.log', 'a+') as fp:
                                                        fp.writelines(json.dumps(response) + '\n')
                                                        urls_response.append(response)
                                    elif response.get('errorNo') == 1:
                                        urls_submitted_for_scan = urls_submitted_for_scan + 1
                                        with open(output_path + 'urls_submitted_for_scan.txt', 'a+') as fp:
                                            fp.writelines(url)
                                    elif response.get('errorNo') == 7026:
                                        urls_found_invalid = urls_found_invalid + 1
                                        with open(output_path + 'urls_found_invalid.txt', 'a+') as fp:
                                            fp.writelines(url)
                                    elif response.get('errorNo') in (7058, 7060, 7062, 7063, 7065, 7066):
                                        state = 'Quota'
                                    elif response.get('errorNo') in (7001, 7002, 7003, 7005, 7006):
                                        self._move_curser(lines=10)
                                        sys.stdout.write('Analysis Aborted\n')
                                        sys.stdout.write('------------------------------------------------------------\n')
                                        sys.stdout.flush()

                                        return state, urls_response
                                    else:
                                        urls_scan_error = urls_scan_error + 1
                                        with open(output_path + 'urls_scan_error.txt', 'a+') as fp:
                                            fp.writelines(url)
                                            fp.writelines('ERROR: {0}\n'.format(state))
                                else:
                                    self._move_curser(lines=10)
                                    sys.stdout.write('Analysis Aborted\n')
                                    sys.stdout.write('------------------------------------------------------------\n')
                                    sys.stdout.flush()

                                    return state, urls_response

                                self._move_curser(lines=10)
                                sys.stdout.write('Now Processing URL: %s ...\n' % url.rstrip()[:128])
                                sys.stdout.write('------------------------------------------------------------\n')
                                sys.stdout.write('Total URLs Submitted So Far: %d\n' % urls_original)
                                sys.stdout.write('URLs Submitted For Live Scan: %d\n' % urls_submitted_for_scan)
                                sys.stdout.write('Malicious URLs Found From Cache: %d\n' % urls_found_malicious)
                                sys.stdout.write('Benign URLs Found From Cache: %d\n' % urls_found_benign)
                                sys.stdout.write('Invalid URLs Found: %d\n' % urls_found_invalid)
                                sys.stdout.write('URLs With API Errors: %d\n' % urls_scan_error)
                                sys.stdout.write('\nPress CTRL+C to Abort!\n')
                                sys.stdout.flush()

                            lookup_results = {
                                'total_count': urls_original,
                                'malicious_count': urls_found_malicious,
                                'benign_count': urls_found_benign,
                                'invalid_count': urls_found_invalid,
                                'error_count': urls_scan_error,
                                'submitted_count': urls_submitted_for_scan
                            }
                            compiled_results["lookup"] = lookup_results

                            if state == 'Quota':
                                self._move_curser(lines=2)
                                sys.stdout.write('------------------------------------------------------------\n')
                                sys.stdout.write('Analysis Aborted\n')
                                sys.stdout.write('------------------------------------------------------------\n')
                                sys.stdout.flush()

                                return state, urls_response

                    pending_list = []
                    if urls_submitted_for_scan:
                        new_file_path = output_path + 'urls_submitted_for_scan.txt'
                        with open(new_file_path, 'r') as submitted_file:
                            pending_list = submitted_file.readlines()

                        urls_scanned = urls_submitted_for_scan
                        urls_scan_completed = 0
                        urls_scan_malicious = 0
                        urls_scan_benign = 0
                        urls_scan_error = 0

                        for retry in range(retries):
                            self._move_curser(lines=2)
                            sys.stdout.write('------------------------------------------------------------\n')
                            sys.stdout.write('Waiting for %d seconds to let the requested live scans finish ...\n' % poll_interval)
                            sys.stdout.write('\nPress CTRL+C to Abort!\n')
                            time.sleep(poll_interval)
                            self._move_curser(lines=2)
                            sys.stdout.write('------------------------------------------------------------\n')
                            self._move_curser(lines=10, direction='down')
                            sys.stdout.flush()

                            new_pending_list = []
                            for url in pending_list:
                                if url.rstrip():
                                    api_data = {
                                        'url': url,
                                        'authkey': self.__api_key
                                    }
                                    state, response = snx_api_request(self.__base_url, URL_SCAN_API, api_data)

                                    if response and isinstance(response, dict):
                                        if response.get('errorNo') == 0:
                                            urls_scan_completed = urls_scan_completed + 1
                                            with open(output_path + 'urls_scanned.txt', 'a+') as fp:
                                                fp.writelines(url)

                                            url_data = response.get('urlData')
                                            threat_data = url_data.get('landingUrl').get('threatData') if 'landingUrl' in url_data else url_data.get('threatData')
                                            if threat_data.get('verdict') == 'Malicious':
                                                urls_scan_malicious = urls_scan_malicious + 1
                                                with open(output_path + 'urls_scanned_malicious.txt', 'a+') as fp:
                                                    fp.writelines(url)
                                                with open(output_path + 'malicious_urls_raw.log', 'a+') as fp:
                                                    fp.writelines(json.dumps(response) + '\n')
                                                    urls_response.append(response)
                                            else:
                                                host = self.split_host_uri(self.normalize_url(url))[1]
                                                data = {
                                                    'host': host,
                                                    'authkey': self.__api_key
                                                }
                                                h_s, h_r = snx_api_request(self.__base_url, HOST_REPUTE_API, data)

                                                if h_r.get('errorNo', 404) == 0:
                                                    host_threat_data = h_r.get('threatData')
                                                    if host_threat_data.get('verdict') == 'Malicious':
                                                        response['urlData']['threatData'] = host_threat_data

                                                        urls_scan_malicious = urls_scan_malicious + 1
                                                        with open(output_path + 'urls_scanned_malicious.txt', 'a+') as fp:
                                                            fp.writelines(url)
                                                        with open(output_path + 'malicious_urls_raw.log', 'a+') as fp:
                                                            fp.writelines(json.dumps(response) + '\n')
                                                            urls_response.append(response)
                                                    else:
                                                        urls_scan_benign = urls_scan_benign + 1
                                                        with open(output_path + 'urls_scanned_benign.txt', 'a+') as fp:
                                                            fp.writelines(url)
                                                        with open(output_path + 'benign_urls_raw.log', 'a+') as fp:
                                                            fp.writelines(json.dumps(response) + '\n')
                                                            urls_response.append(response)
                                        elif response.get('errorNo') == 1:
                                            new_pending_list.append(url)
                                            with open(output_path + f'urls_scan_pending_{retry}.txt', 'a+') as fp:
                                                fp.writelines(url)
                                        elif response.get('errorNo') in (7058, 7060, 7062, 7063, 7065, 7066):
                                            state = 'Quota'
                                        elif response.get('errorNo') in (7001, 7002, 7003, 7005, 7006):
                                            self._move_curser(lines=10)
                                            sys.stdout.write('Analysis Aborted\n')
                                            sys.stdout.write('------------------------------------------------------------\n')
                                            sys.stdout.flush()

                                            return state, urls_response
                                        else:
                                            urls_scan_error = urls_scan_error + 1
                                            with open(output_path + 'urls_scan_error.txt', 'a+') as fp:
                                                fp.writelines(url)
                                                fp.writelines('ERROR: {0}\n'.format(state))
                                    else:
                                        self._move_curser(lines=10)
                                        sys.stdout.write('Analysis Aborted\n')
                                        sys.stdout.write(
                                            '------------------------------------------------------------\n')
                                        sys.stdout.flush()

                                        return state, urls_response

                                    self._move_curser(lines=10)
                                    sys.stdout.write('Now Reprocessing URL: %s ...\n' % url.rstrip()[:128])
                                    sys.stdout.write('------------------------------------------------------------\n')
                                    sys.stdout.write('Total URLs Scanned So Far: %d\n' % urls_scanned)
                                    sys.stdout.write('Malicious URLs Found From Scan: %d\n' % urls_scan_malicious)
                                    sys.stdout.write('Benign URLs Found From Scan: %d\n' % urls_scan_benign)
                                    sys.stdout.write('URLs With Scan Completed: %d\n' % urls_scan_completed)
                                    sys.stdout.write('URLs With Scan Still Pending: %d\n' % len(new_pending_list))
                                    sys.stdout.write('URLs With Scan Errors: %d\n' % urls_scan_error)
                                    sys.stdout.write('\nPress CTRL+C to Abort!\n')
                                    sys.stdout.flush()

                                urls_still_pending = len(pending_list) - urls_scan_completed - urls_scan_error
                                scan_results = {
                                    'total_count': urls_scanned,
                                    'malicious_count': urls_scan_malicious,
                                    'benign_count': urls_scan_benign,
                                    'pending_count': urls_still_pending,
                                    'completed_count': urls_scan_completed,
                                    'error_count': urls_scan_error
                                }
                                compiled_results['scan'] = scan_results

                                if state == 'Quota':
                                    self._move_curser(lines=2)
                                    sys.stdout.write('------------------------------------------------------------\n')
                                    sys.stdout.write('Analysis Aborted\n')
                                    sys.stdout.write('------------------------------------------------------------\n')
                                    sys.stdout.flush()

                                    return state, urls_response

                            compiled_results['scan']['pending_count'] = len(new_pending_list)
                            if len(new_pending_list):
                                pending_list = new_pending_list
                            else:
                                break

                    self._move_curser(lines=2)
                    sys.stdout.write('------------------------------------------------------------\n')
                    sys.stdout.write('Analysis Completed\n')
                    sys.stdout.write('------------------------------------------------------------\n')
                    sys.stdout.flush()

                    return "Success", urls_response
                else:
                    return "The provided file is either invalid or empty.", []
            else:
                return "Please provide a valid output directory.", []
        except KeyboardInterrupt:
            self._move_curser(lines=2)
            sys.stdout.write('----------------------------------------------------------\n')
            sys.stdout.write('Analysis Interrupted\n')
            sys.stdout.write('------------------------------------------------------------\n')
            sys.stdout.flush()

            return "Success", urls_response
        except Exception as e:
            return str(e)

        #
        # if state != 'Success' or response.get('errorNo') == 1:
        #     return state, [response]
        #
        # if response.get('swlData') is not None and response.get('swlData').get('swlStatus') == 1:
        #     return state, [response]
        #
        # if extended_info == 'true':
        #     scanid = response.get('urlData').get('scanId')
        #     api_data = {
        #         'scanid': scanid,
        #         'authkey': self.__api_key
        #     }
        #     sta_html, response_html = snx_api_request(self.__base_url, DL_HTML_API, api_data)
        #     sta_text, response_text = snx_api_request(self.__base_url, DL_TEXT_API, api_data)
        #
        #     api_data['resolution'] = 'medium'
        #     sta_sc, response_sc = snx_api_request(self.__base_url, DL_SC_API, api_data)
        #
        #     return state, [response, response_sc, response_html, response_text]
        # else:
        #     return state, [response]

    def normalize_url(self, url, default='http'):
        """
        Cleanup given URL and replace its email parameter with dummy if found.
        @param url: URL to normalize. (string)
        @param default: Default protocol if not found. (string)
        @return: Normalized URL. (string)
        """
        url = url.strip()
        if not url.lower().startswith(SUPPORTED_PROTO) and default:
            url = '{0}://'.format(default) + url.lstrip('://')
        try:
            normalized = w3url.safe_url_string(url)
        except ValueError:
            return ''
        if self.__url_regex.match(normalized) is None:
            return ''
        # http://abc.com
        # http://abc.com/
        # http://abc.com/something/
        # http://abc.com/something
        parsed = urlparse.urlsplit(normalized)
        try:
            scheme = parsed.scheme
            netloc = parsed.netloc
            _ = parsed.password
            _ = parsed.username
            domain = parsed.hostname
            _ = parsed.port
        except ValueError:
            return ''
        base_url = scheme + '://' + netloc
        if normalized == base_url:
            normalized += '/'
        normalized = normalized.replace(base_url, base_url.lower(), 1)
        decoded_url = unquote(normalized)
        email_lookup = self.__email_regex.findall(decoded_url)
        for i, matched in enumerate(email_lookup):
            if not i and domain.endswith(matched):
                continue
            if not matched.endswith(INVALID_EMAIL_TLD):
                quoted_match = matched.replace('@', '%40', 1)
                normalized = normalized.replace(matched, DUMMY_EMAIL)
                normalized = normalized.replace(quoted_match, DUMMY_EMAIL)
        return normalized

    @staticmethod
    def split_host_uri(url):
        """
        Extract domain and URI from given URL.
        @param url: URL to split. (string)
        @return: Set of protocol, host and URI part. (tuple)
        """
        parsed = urlparse.urlparse(url)
        scheme = parsed.scheme
        host = parsed.netloc
        if not host:
            return None, None, None
        uri = url.split(host, 1)[-1]
        if not uri:
            uri = '/'
        return scheme, host, uri

    @staticmethod
    def _get_url_validator():
        """
        Get regex pattern that can validate a URL.
        @return: Compiled regex to validate URL. (object)
        """
        # removed unicode and used regex only from django validator
        # github.com/django/django/blob/stable/3.0.x/django/core/validators.py#L76
        # IP patterns
        ipv4_re = (r'(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)'
                   r'(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}')
        ipv6_re = r'\[[0-9a-f:\.]+\]'  # (simple regex, validated later)
        # Host patterns
        hostname_re = r'[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?'
        # Max length for domain labels is 63 characters per RFC 1034 sec. 3.1
        domain_re = r'(?:\.(?![-_])[a-z0-9-_]{1,63}(?<![-_]))*'
        tld_re = (
            r'\.'  # dot
            r'(?!-)'  # can't start with a dash
            r'(?:[a-z-0-9]{2,63}'  # domain label
            r'|xn--[a-z0-9]{1,59})'  # or punycode label
            r'(?<!-)'  # can't end with a dash
            r'\.?'  # may have a trailing dot
        )
        host_re = '(' + hostname_re + domain_re + tld_re + '|localhost)'
        # Compile regex
        rgx = re.compile(
            r'^(?:[a-z0-9\.\-\+]*)://'  # scheme is validated separately
            r'(?:[^\s:@/]+(?::[^\s:@/]*)?@)?'  # user:pass authentication
            r'(?:' + ipv4_re + '|' + ipv6_re + '|' + host_re + ')'
                                                               r'(?::\d{2,5})?'  # port
                                                               r'(?:[/?#][^\s]*)?'  # resource path
                                                               r'\Z', re.IGNORECASE)

        return rgx

    @staticmethod
    def _move_curser(lines, direction='up'):
        """
        Moves the terminal curser up or down by number of lines.
        :param lines: Number of lines.
        :param direction: Up or Down.
        """
        if direction == 'up':
            for _ in range(lines):
                sys.stdout.write(CURSOR_UP_ONE)
                sys.stdout.write(ERASE_LINE)
        else:
            for _ in range(lines):
                sys.stdout.write('\n')

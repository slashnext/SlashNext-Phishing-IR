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
Created on December 09, 2019

@author: Saadat Abid
"""

from __future__ import unicode_literals

import os
import base64
import pyperclip

from SlashNextPhishingIR import SlashNextPhishingIR

from datetime import datetime
from pyfiglet import figlet_format
from textwrap import wrap
from terminaltables import DoubleTable

from prompt_toolkit.application import Application, get_app
from prompt_toolkit.document import Document
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.filters import Condition
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.widgets import Button, TextArea
from prompt_toolkit.layout.containers import (
    Float, FloatContainer, HSplit, Window, WindowAlign, VSplit, ConditionalContainer,
)


CONF_DIRECTORY = os.getcwd() + '/slashnext_oti/conf'
OUT_DIRECTORY = os.getcwd() + '/slashnext_oti/evidence'
DUMP_DIRECTORY = os.getcwd() + '/slashnext_oti/dump'

SUPPORTED_ACTIONS = [
    "slashnext-api-quota",
    "slashnext-host-reputation",
    "slashnext-host-report",
    "slashnext-host-urls",
    "slashnext-url-reputation",
    "slashnext-url-scan",
    "slashnext-url-scan-sync",
    "slashnext-scan-report",
    "slashnext-download-screenshot",
    "slashnext-download-html",
    "slashnext-download-text",
]
PARAMETERS = [
    "host=",
    "url=",
    "scanid=",
    "resolution=",
    "timeout=",
    "limit=",
    "extended_info=",
]

COMPLETER = SUPPORTED_ACTIONS + PARAMETERS

# Style set
style_set = Style(
    [
        # ("title", "bg:#000000 #1b03a3"),
        # ("subtitle", "bg:#000000 #1b03a3"),
        # ("output", "bg:#000044 #ffffff"),
        # ("input", "bg:#000000 #ffffff"),
        # ("line", "bg:#000000 #1b03a3"),
        # ("conf_title", "bg:#000000 #1b03a3"),
        # ("conf_prompt", "bg:#000000 #1b03a3"),
        # ("conf_input", "bg:#1b03a3 #000000"),
        ("conf_notice", "blink"),
        ("conf_input", "reverse"),
    ]
)

# The auto-completer for commands/actions.
action_set = WordCompleter(
    COMPLETER,
    ignore_case=True,
    WORD=True
)

# Prerequisites ########################################################################################################
if os.path.exists(CONF_DIRECTORY) is False:
    os.makedirs(CONF_DIRECTORY)

if os.path.exists(OUT_DIRECTORY) is False:
    os.makedirs(OUT_DIRECTORY)

if os.path.exists(DUMP_DIRECTORY) is False:
    os.makedirs(DUMP_DIRECTORY)
########################################################################################################################

# SlashNext OTI Backend ################################################################################################
snx_oti_backend = SlashNextPhishingIR(CONF_DIRECTORY)
########################################################################################################################

# SlashNext OTI Configuration Menu Layout ##############################################################################


class ConfigurationMenuState:
    def __init__(self, is_active):
        self.is_active = is_active

    def get_state(self):
        return self.is_active

    def toggle_state(self):
        if self.is_active is True:
            self.is_active = False
        else:
            self.is_active = True

    def set_state(self, is_active):
        self.is_active = is_active


conf_menu_state = ConfigurationMenuState(True)

conf_title = Window(FormattedTextControl('SlashNext Phishing IR Configuration'),
                    height=1, width=40, align=WindowAlign.CENTER, style="class:conf_title")

conf_prompt_conf = Window(FormattedTextControl('Configuration Directory'),
                          height=1, align=WindowAlign.LEFT, style="class:conf_prompt")

conf_input_conf = TextArea(height=1, prompt='', multiline=False, wrap_lines=False, style="class:conf_input",
                           focusable=True, focus_on_click=True)

conf_prompt_out = Window(FormattedTextControl('Evidence Directory'),
                         height=1, align=WindowAlign.LEFT, style="class:conf_prompt")

conf_input_out = TextArea(height=1, prompt='', multiline=False, wrap_lines=False, style="class:conf_input",
                          focusable=True, focus_on_click=True)

conf_prompt_api_key = Window(FormattedTextControl('SlashNext API Key'),
                             height=1, align=WindowAlign.LEFT, style="class:conf_prompt")

conf_input_api_key = TextArea(height=1, prompt='', multiline=False, wrap_lines=False, style="class:conf_input",
                              focusable=True, focus_on_click=True, password=True)

conf_prompt_base_url = Window(FormattedTextControl('SlashNext Base URL'),
                              height=1, align=WindowAlign.LEFT, style="class:conf_prompt")

conf_input_base_url = TextArea(height=1, prompt='', multiline=False, wrap_lines=False,
                               style="class:conf_input", focusable=True, focus_on_click=True)

conf_input_base_url.text = 'https://oti.slashnext.cloud/api'

conf_status = TextArea(height=5, multiline=True, wrap_lines=True, style="class:conf_notice")

separator = Window(height=1, width=1, align=WindowAlign.CENTER, style="class:conf_prompt")

terminator = Window(align=WindowAlign.CENTER, style="class:conf_prompt")

line = Window(height=1, char="─", style="class:line")


def do_close():
    conf_menu_state.set_state(False)


def do_ok():
    if conf_input_api_key.text is None or conf_input_api_key.text.strip() == '':
        conf_status.text = 'WARNING\n'\
            'Please provide a valid API Key or contact support@slashnext.com'
    elif conf_input_base_url.text is None or conf_input_base_url.text.strip() == '':
        conf_status.text = 'WARNING\n'\
            'Please provide a valid Base URL or contact support@slashnext.com'
    else:
        snx_oti_backend.set_conf(conf_input_api_key.text.strip(), conf_input_base_url.text.strip())
        snx_oti_backend.load_conf()
        status, details = snx_oti_backend.test()
        conf_status.text = 'SlashNext configuration has been updated'


def do_test():
    if conf_input_api_key.text is None or conf_input_api_key.text.strip() == '':
        conf_status.text = 'WARNING\n'\
            'Please provide a valid API Key or contact support@slashnext.com'
    elif conf_input_base_url.text is None or conf_input_base_url.text.strip() == '':
        conf_status.text = 'WARNING\n'\
            'Please provide a valid Base URL or contact support@slashnext.com'
    else:
        snx_oti_backend.set_conf(conf_input_api_key.text.strip(), conf_input_base_url.text.strip())
        snx_oti_backend.load_conf()
        status, details = snx_oti_backend.test()
        conf_status.text = status.upper() + '\n' + details


conf_ok_button = Button('OK', handler=do_ok)
conf_close_button = Button('Close', handler=do_close)
conf_test_button = Button('Test', handler=do_test)

conf_buttons = ConditionalContainer(
    content=VSplit(
        [
            separator,
            conf_test_button,
            separator,
            separator,
            separator,
            separator,
            separator,
            conf_close_button,
            separator,
            conf_ok_button,
            separator,
        ]
    ),
    filter=Condition(lambda: conf_menu_state.get_state()),
)

conf_menu = ConditionalContainer(
    content=HSplit(
        [
            line,
            conf_title,
            line,
            # VSplit(
            #     [
            #         separator,
            #         conf_prompt_conf,
            #         separator,
            #
            #     ]
            # ),
            # separator,
            # VSplit(
            #     [
            #         separator,
            #         conf_input_conf,
            #         separator,
            #
            #     ]
            # ),
            # separator,
            # VSplit(
            #     [
            #         separator,
            #         conf_prompt_out,
            #         separator,
            #
            #     ]
            # ),
            # separator,
            # VSplit(
            #     [
            #         separator,
            #         conf_input_out,
            #         separator,
            #
            #     ]
            # ),
            # separator,
            VSplit(
                [
                    separator,
                    conf_prompt_api_key,
                    separator,

                ]
            ),
            separator,
            VSplit(
                [
                    separator,
                    conf_input_api_key,
                    separator,

                ]
            ),
            separator,
            VSplit(
                [
                    separator,
                    conf_prompt_base_url,
                    separator,

                ]
            ),
            separator,
            VSplit(
                [
                    separator,
                    conf_input_base_url,
                    separator,

                ]
            ),
            separator,
            separator,
            VSplit(
                [
                    separator,
                    conf_status,
                    separator,

                ]
            ),
            terminator,
            conf_buttons,
            separator,
        ]
    ),
    filter=Condition(lambda: conf_menu_state.get_state()),
)
########################################################################################################################

# Auto-Loading of Configuration Menu at Start-up #######################################################################
snx_oti_backend.load_conf()
status_oti, details_oti = snx_oti_backend.get_status()

if status_oti != 'ok':
    conf_menu_state.set_state(True)
    conf_status.text = status_oti.upper() + '\n' + details_oti
else:
    status_oti, details_oti = snx_oti_backend.test()
    if status_oti != 'ok':
        conf_menu_state.set_state(True)

        if snx_oti_backend.base_url is not None and snx_oti_backend.base_url != '':
            conf_input_base_url.text = snx_oti_backend.base_url
        if snx_oti_backend.api_key is not None and snx_oti_backend.api_key != '':
            conf_input_api_key.text = snx_oti_backend.api_key

        conf_status.text = status_oti.upper() + '\n' + details_oti
    else:
        conf_menu_state.set_state(False)
########################################################################################################################

# The Output Results Formatting ########################################################################################


def get_api_quota_table(response_list):
    data_list = []
    header = [
        'Licenced Quota',
        'Remaining Quota',
        'Expiration Date',
    ]
    data_list.append(header)
    response = response_list[0]
    quota_data = response.get('quotaDetails')
    data = [
        quota_data.get('licensedQuota'),
        quota_data.get('remainingQuota'),
        quota_data.get('expiryDate'),
    ]
    data_list.append(data)

    api_quota = DoubleTable(data_list)
    api_quota.padding_left = 1
    api_quota.padding_right = 1
    api_quota.inner_column_border = True
    api_quota.inner_row_border = True

    return api_quota.table + '\n\nNote: ' + quota_data.get('note')


def get_host_reputation_table(response_list):
    data_list = []
    header = [
        'Verdict',
        'Threat Status',
        'Threat Name',
        'Threat Type',
        'First Seen',
        'Last Seen',
    ]
    data_list.append(header)
    response = response_list[0]
    threat_data = response.get('threatData')
    data = [
        threat_data.get('verdict'),
        threat_data.get('threatStatus'),
        threat_data.get('threatName'),
        threat_data.get('threatType'),
        threat_data.get('firstSeen'),
        threat_data.get('lastSeen'),
    ]
    data_list.append(data)

    host_reputation = DoubleTable(data_list)
    host_reputation.padding_left = 1
    host_reputation.padding_right = 1
    host_reputation.inner_column_border = True
    host_reputation.inner_row_border = True

    return host_reputation.table


def get_host_report_table(response_list):
    host_reputation = get_host_reputation_table([response_list[0]])

    if len(response_list) == 5:
        response = response_list[1]

        if response.get('urlDataList') is not None:
            latest_url = get_host_urls_table([response_list[1]])
            name = response.get('urlDataList')[0].get('scanId')
        else:
            latest_url = get_scan_report_table([response_list[1]])
            name = response.get('urlData').get('scanId')

        download_sc = get_download_sc_file([response_list[2]], name)
        download_html = get_download_html_file([response_list[3]], name)
        download_text = get_download_text_file([response_list[4]], name)

        return host_reputation + '\n\nLatest URL\n\n' + latest_url + \
            '\n\nWebpage Forensics\n\n' + download_sc + '\n' + download_html + '\n' + download_text
    else:
        return host_reputation


def get_host_urls_table(response_list):
    data_list = []
    header = [
        'URL',
        'Type',
        'Verdict',
        'Threat Status',
        'Scan ID',
        'Threat Name',
        'Threat Type',
        'First Seen',
        'Last Seen',
    ]
    data_list.append(header)
    response = response_list[0]
    url_list = response.get('urlDataList')
    for url in url_list:
        threat_data = url.get('threatData')
        data = [
            url.get('url'),
            'Scanned URL',
            threat_data.get('verdict'),
            threat_data.get('threatStatus'),
            url.get('scanId'),
            threat_data.get('threatName'),
            threat_data.get('threatType'),
            threat_data.get('firstSeen'),
            threat_data.get('lastSeen'),
        ]
        data_list.append(data)

        if url.get('finalUrl') is not None:
            data = [
                url.get('finalUrl'),
                'Final URL',
                threat_data.get('verdict'),
                threat_data.get('threatStatus'),
                '-',
                '-',
                '-',
                '-',
                '-',
            ]
            data_list.append(data)

        if url.get('landingUrl') is not None:
            landing_url = url.get('landingUrl')
            threat_data = landing_url.get('threatData')
            data = [
                landing_url.get('url'),
                'Redirected URL',
                threat_data.get('verdict'),
                threat_data.get('threatStatus'),
                landing_url.get('scanId'),
                threat_data.get('threatName'),
                threat_data.get('threatType'),
                threat_data.get('firstSeen'),
                threat_data.get('lastSeen'),
            ]
            data_list.append(data)

    host_urls = DoubleTable(data_list)
    host_urls.padding_left = 1
    host_urls.padding_right = 1
    host_urls.inner_column_border = True
    host_urls.inner_row_border = True

    for i, data in enumerate(data_list):
        if i > 0:
            wrapped_url = '\n'.join(wrap(data[0], 35))
            wrapped_t = '\n'.join(wrap(data[1], 10))
            wrapped_sid = '\n'.join(wrap(data[4], 18))
            wrapped_tn = '\n'.join(wrap(data[5], 12))
            wrapped_tt = '\n'.join(wrap(data[6], 12))
            wrapped_fs = '\n'.join(wrap(data[7], 12))
            wrapped_ls = '\n'.join(wrap(data[8], 12))

            host_urls.table_data[i][0] = wrapped_url
            host_urls.table_data[i][1] = wrapped_t
            host_urls.table_data[i][4] = wrapped_sid
            host_urls.table_data[i][5] = wrapped_tn
            host_urls.table_data[i][6] = wrapped_tt
            host_urls.table_data[i][7] = wrapped_fs
            host_urls.table_data[i][8] = wrapped_ls

    return host_urls.table


def get_url_reputation_table(response_list):
    data_list = []
    header = [
        'URL',
        'Type',
        'Verdict',
        'Threat Status',
        'Threat Name',
        'Threat Type',
        'First Seen',
        'Last Seen',
    ]
    data_list.append(header)
    response = response_list[0]

    normalize_msg = ''
    if response.get('normalizeData').get('normalizeStatus') == 1:
        normalize_msg = response.get('normalizeData').get('normalizeMessage') + '\n'

    url = response.get('urlData')
    threat_data = url.get('threatData')
    data = [
        url.get('url'),
        'Scanned URL',
        threat_data.get('verdict'),
        threat_data.get('threatStatus'),
        threat_data.get('threatName'),
        threat_data.get('threatType'),
        threat_data.get('firstSeen'),
        threat_data.get('lastSeen'),
    ]
    data_list.append(data)

    if url.get('finalUrl') is not None:
        data = [
            url.get('finalUrl'),
            'Final URL',
            threat_data.get('verdict'),
            threat_data.get('threatStatus'),
            '-',
            '-',
            '-',
            '-',
        ]
        data_list.append(data)

    if url.get('landingUrl') is not None:
        landing_url = url.get('landingUrl')
        threat_data = landing_url.get('threatData')
        data = [
            landing_url.get('url'),
            'Redirected URL',
            threat_data.get('verdict'),
            threat_data.get('threatStatus'),
            threat_data.get('threatName'),
            threat_data.get('threatType'),
            threat_data.get('firstSeen'),
            threat_data.get('lastSeen'),
        ]
        data_list.append(data)

    url_reputation_report = DoubleTable(data_list)
    url_reputation_report.padding_left = 1
    url_reputation_report.padding_right = 1
    url_reputation_report.inner_column_border = True
    url_reputation_report.inner_row_border = True

    for i, data in enumerate(data_list):
        if i > 0:
            wrapped_url = '\n'.join(wrap(data[0], 35))
            wrapped_t = '\n'.join(wrap(data[1], 10))
            wrapped_tn = '\n'.join(wrap(data[4], 12))
            wrapped_tt = '\n'.join(wrap(data[5], 12))
            wrapped_fs = '\n'.join(wrap(data[6], 12))
            wrapped_ls = '\n'.join(wrap(data[7], 12))

            url_reputation_report.table_data[i][0] = wrapped_url
            url_reputation_report.table_data[i][1] = wrapped_t
            url_reputation_report.table_data[i][4] = wrapped_tn
            url_reputation_report.table_data[i][5] = wrapped_tt
            url_reputation_report.table_data[i][6] = wrapped_fs
            url_reputation_report.table_data[i][7] = wrapped_ls

    return normalize_msg + url_reputation_report.table


def get_url_scan_table(response_list):
    return get_scan_report_table(response_list, source=1)


def get_url_scan_sync_table(response_list):
    return get_scan_report_table(response_list, source=2)


def get_scan_report_table(response_list, source=0):
    data_list = []
    header = [
        'URL',
        'Type',
        'Verdict',
        'Threat Status',
        'Scan ID',
        'Threat Name',
        'Threat Type',
        'First Seen',
        'Last Seen',
    ]
    data_list.append(header)
    response = response_list[0]

    normalize_msg = ''
    if response.get('errorNo') != 1:
        if response.get('normalizeData').get('normalizeStatus') == 1:
            normalize_msg = response.get('normalizeData').get('normalizeMessage') + '\n'

        url = response.get('urlData')
        threat_data = url.get('threatData')
        name = url.get('scanId')
        data = [
            url.get('url'),
            'Scanned URL',
            threat_data.get('verdict'),
            threat_data.get('threatStatus'),
            name,
            threat_data.get('threatName'),
            threat_data.get('threatType'),
            threat_data.get('firstSeen'),
            threat_data.get('lastSeen'),
        ]
        data_list.append(data)

        if url.get('finalUrl') is not None:
            data = [
                url.get('finalUrl'),
                'Final URL',
                threat_data.get('verdict'),
                threat_data.get('threatStatus'),
                '-',
                '-',
                '-',
                '-',
                '-',
            ]
            data_list.append(data)

        if url.get('landingUrl') is not None:
            landing_url = url.get('landingUrl')
            threat_data = landing_url.get('threatData')
            data = [
                landing_url.get('url'),
                'Redirected URL',
                threat_data.get('verdict'),
                threat_data.get('threatStatus'),
                landing_url.get('scanId'),
                threat_data.get('threatName'),
                threat_data.get('threatType'),
                threat_data.get('firstSeen'),
                threat_data.get('lastSeen'),
            ]
            data_list.append(data)

        scan_report = DoubleTable(data_list)
        scan_report.padding_left = 1
        scan_report.padding_right = 1
        scan_report.inner_column_border = True
        scan_report.inner_row_border = True

        for i, data in enumerate(data_list):
            if i > 0:
                wrapped_url = '\n'.join(wrap(data[0], 35))
                wrapped_t = '\n'.join(wrap(data[1], 10))
                wrapped_sid = '\n'.join(wrap(data[4], 18))
                wrapped_tn = '\n'.join(wrap(data[5], 12))
                wrapped_tt = '\n'.join(wrap(data[6], 12))
                wrapped_fs = '\n'.join(wrap(data[7], 12))
                wrapped_ls = '\n'.join(wrap(data[8], 12))

                scan_report.table_data[i][0] = wrapped_url
                scan_report.table_data[i][1] = wrapped_t
                scan_report.table_data[i][4] = wrapped_sid
                scan_report.table_data[i][5] = wrapped_tn
                scan_report.table_data[i][6] = wrapped_tt
                scan_report.table_data[i][7] = wrapped_fs
                scan_report.table_data[i][8] = wrapped_ls
    else:
        if source == 1:
            return 'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'\
                   'Please check back later using "slashnext-scan-report" action with Scan ID = {0} or running the ' \
                   'same "slashnext-url-scan" action one more time'.format(response.get('urlData').get('scanId'))
        elif source == 2:
            return 'Your Url Scan request is submitted to the cloud and is taking longer than expected to complete.\n' \
                   'Please check back later using "slashnext-scan-report" action with Scan ID = {0} or running the ' \
                   'same "slashnext-url-scan-sync" action one more time'.format(response.get('urlData').get('scanId'))
        else:
            return 'Your Url Scan request is submitted to the cloud and is taking longer than expected to complete.\n' \
                   'Please check back later using "slashnext-scan-report" action with Scan ID = {0} one more ' \
                   'time'.format(response.get('urlData').get('scanId'))

    if len(response_list) == 4:
        download_sc = get_download_sc_file([response_list[1]], name)
        download_html = get_download_html_file([response_list[2]], name)
        download_text = get_download_text_file([response_list[3]], name)

        return normalize_msg + scan_report.table + '\n\nWebpage Forensics\n\n' + \
            download_sc + '\n' + download_html + '\n' + download_text
    else:
        return normalize_msg + scan_report.table


def get_download_sc_file(response_list, name):
    response = response_list[0]
    if response.get('errorNo') == 0:
        try:
            with open(OUT_DIRECTORY + '/' + name + '.jpeg', 'wb') as file_handle:
                file_handle.write(base64.b64decode(response.get('scData').get('scBase64')))

            return 'JPEG saved as: ' + OUT_DIRECTORY + '/' + name + '.jpeg'

        except PermissionError:
            return 'Permission denied, please acquire the proper privileges for workspace and retry'
        except Exception as e:
            return 'ERROR: {0}'.format(str(e))
    elif response.get('errorNo') == 1:
        return 'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n' \
               'Please check back later using "slashnext-download-screenshot" action with Scan ID = {0}'.format(name)
    else:
        return 'ERROR: {0}'.format(response.get('errorMsg'))


def get_download_html_file(response_list, name):
    response = response_list[0]
    if response.get('errorNo') == 0:
        try:
            with open(OUT_DIRECTORY + '/' + name + '.html', 'wb') as file_handle:
                file_handle.write(base64.b64decode(response.get('htmlData').get('htmlBase64')))

            return 'HTML saved as: ' + OUT_DIRECTORY + '/' + name + '.html'

        except PermissionError:
            return 'Permission denied, please acquire the proper privileges for workspace and retry'
        except Exception as e:
            return 'ERROR: {0}'.format(str(e))
    elif response.get('errorNo') == 1:
        return 'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n' \
               'Please check back later using "slashnext-download-html" action with Scan ID = {0}'.format(name)
    else:
        return 'ERROR: {0}'.format(response.get('errorMsg'))


def get_download_text_file(response_list, name):
    response = response_list[0]
    if response.get('errorNo') == 0:
        try:
            with open(OUT_DIRECTORY + '/' + name + '.txt', 'wb') as file_handle:
                file_handle.write(base64.b64decode(response.get('textData').get('textBase64')))

            return 'Text saved as: ' + OUT_DIRECTORY + '/' + name + '.txt'
        except PermissionError:
            return 'Permission denied, please acquire the proper privileges for workspace and retry'
        except Exception as e:
            return 'ERROR: {0}'.format(str(e))
    elif response.get('errorNo') == 1:
        return 'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n' \
               'Please check back later using "slashnext-download-text" action with Scan ID = {0}'.format(name)
    else:
        return 'ERROR: {0}'.format(response.get('errorMsg'))


def get_line():
    return '\n\n─────────────────────────────────────────────────────────────────────────────────────────────────────' \
           '───────────────────────────────────────────────\n'


def prepare_results(action, parameter, details, response_list):
    action_lower = action.lower()

    if action_lower == 'slashnext-api-quota':
        return '\n' + details + '\n\n' + \
               get_api_quota_table(response_list)
    elif action_lower == 'slashnext-host-reputation':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
               get_host_reputation_table(response_list)
    elif action_lower == 'slashnext-host-report':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
               get_host_report_table(response_list)
    elif action_lower == 'slashnext-host-urls':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
               get_host_urls_table(response_list)
    elif action_lower == 'slashnext-url-reputation':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
               get_url_reputation_table(response_list)
    elif action_lower == 'slashnext-url-scan':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
                get_url_scan_table(response_list)
    elif action_lower == 'slashnext-url-scan-sync':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
                get_url_scan_sync_table(response_list)
    elif action_lower == 'slashnext-scan-report':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
                get_scan_report_table(response_list)
    elif action_lower == 'slashnext-download-screenshot':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
               get_download_sc_file(response_list, parameter.lstrip('scanid='))
    elif action_lower == 'slashnext-download-html':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
               get_download_html_file(response_list, parameter.lstrip('scanid='))
    elif action_lower == 'slashnext-download-text':
        return '\n' + details + '\n\n' + parameter + '\n\n' + \
               get_download_text_file(response_list, parameter.lstrip('scanid='))
    else:
        return '\n' + details + '\n\n' + parameter + '\n\n' + str(response_list[0])
########################################################################################################################

# The Main OTI Console Layout ##########################################################################################


title = Window(FormattedTextControl(figlet_format('SlashNext')),
               height=6, align=WindowAlign.CENTER, style="class:title")

subtitle = Window(FormattedTextControl('SlashNext Phishing Incident Response Console --- v1.1.0'),
                  height=1, align=WindowAlign.CENTER, style="class:subtitle")

status_sc = TextArea(text="Welcome to SlashNext Phishing Incident Response Console", style="class:output")

output_sc = TextArea(style="class:output", scrollbar=True, focus_on_click=True, read_only=True)

input_sc = TextArea(height=1, prompt=">> ", style="class:input",
                    multiline=False, wrap_lines=True, focus_on_click=True, completer=action_set)


def execute_action():
    if input_sc.text is None or input_sc.text.strip() == '':
        pass
    else:
        status, details = snx_oti_backend.get_status()

        action_list = input_sc.text.split(' > ')

        action_str = action_list[0]

        active_history = output_sc.text
        new_action = '\nACTION: ' + action_str

        if status == 'ok':
            status_sc.text = 'Working on it'
            status, details, response_list = snx_oti_backend.execute(action_str)

            if status != 'ok':
                action_output = '\n' + status.upper() + ': ' + details
            else:
                if len(action_str.strip().split()) == 1:
                    action_output = '\n' + prepare_results(action_str.strip().split()[0].strip(),
                                                           '',
                                                           details,
                                                           response_list)
                else:
                    action_output = '\n' + prepare_results(action_str.strip().split()[0].strip(),
                                                           action_str.strip().split()[1].strip(),
                                                           details,
                                                           response_list)

            status_sc.text = 'If you have any questions, please contact us at support@slashnext.com'

        else:
            action_output = '\nERROR: ' + 'Please provide a valid configuration or contact support@slashnext.com'
            conf_menu_state.set_state(True)

        result_output = new_action + action_output

        if len(action_list) == 2:
            secondary_action_str = action_list[1]

            secondary_action_list = secondary_action_str.strip().split()
            if secondary_action_list[0].strip() == 'dump':
                try:
                    if len(secondary_action_list) == 1:
                        now = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
                        with open(DUMP_DIRECTORY + '/dump_' + now + '.txt', 'w+') as file_handle:
                            file_handle.write(result_output)
                        result_output += '\n\nDump has been created at ' + DUMP_DIRECTORY + '/dump_' + now + '.txt'
                    elif len(secondary_action_list) == 2:
                        with open(DUMP_DIRECTORY + '/' + secondary_action_list[1].strip(), 'w+') as file_handle:
                            file_handle.write(result_output)
                        result_output += '\n\nDump has been created at ' + DUMP_DIRECTORY + '/' + secondary_action_list[1].strip()
                    else:
                        result_output += '\n\nSecondary action "dump" does not accept more than one parameter'
                except PermissionError:
                    result_output += '\n\nPermission denied, please acquire the proper privileges for workspace and retry'
                except Exception as e:
                    result_output += '\n\nERROR: {0}'.format(str(e))

            elif secondary_action_list[0].strip() == 'copy':
                if len(secondary_action_list) == 1:
                    pyperclip.copy(result_output)
                    result_output += '\n\nAction output has been copied to clipboard'
                else:
                    result_output += '\n\nSecondary action "copy" does not accept any parameters'
            else:
                result_output += '\n\nInvalid secondary action i.e. "{0}"'.format(secondary_action_list[0].strip())

        result_output += get_line()
        result_output = active_history + result_output

        output_sc.buffer.set_document(
            value=Document(text=result_output, cursor_position=len(result_output)),
            bypass_readonly=True)


def do_exec():
    execute_action()
    input_sc.buffer.append_to_history()
    input_sc.buffer.reset()


def do_clear():
    output_sc.buffer.set_document(
        value=Document(text='', cursor_position=0), bypass_readonly=True)

    status_sc.text = 'All cleared'


def do_copy():
    text = output_sc.buffer.copy_selection()

    if text.text is None or text.text == '':
        pyperclip.copy(output_sc.text)
        status_sc.text = 'Entire output has been copied to clipboard'
    else:
        pyperclip.copy(text.text)
        status_sc.text = 'Selected text has been copied to clipboard'


def do_dump():
    try:
        now = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        with open(DUMP_DIRECTORY + '/dump_' + now + '.txt', 'w+') as file_handle:
            file_handle.write(output_sc.text)

        status_sc.text = 'Dump has been created at ' + DUMP_DIRECTORY + '/dump_' + now + '.txt'
    except PermissionError:
        status_sc.text = 'Permission denied, please acquire the proper privileges for workspace and retry'
    except Exception as e:
        status_sc.text = 'ERROR: {0}'.format(str(e))


def do_conf():
    if snx_oti_backend.base_url is not None and snx_oti_backend.base_url != '':
        conf_input_base_url.text = snx_oti_backend.base_url
    if snx_oti_backend.api_key is not None and snx_oti_backend.api_key != '':
        conf_input_api_key.text = snx_oti_backend.api_key

    conf_status.text = ''

    conf_menu_state.toggle_state()


def do_exit():
    get_app().exit()


exec_button = Button('Exec', handler=do_exec, width=8)
clear_button = Button('Clear', handler=do_clear, width=9)
copy_button = Button('Copy', handler=do_copy, width=8)
dump_button = Button('Dump', handler=do_dump, width=8)
conf_button = Button('Conf', handler=do_conf, width=8)
exit_button = Button('Exit', handler=do_exit, width=8)

menu_bar_body = ConditionalContainer(
    content=VSplit(
        [
            separator,
            status_sc,
            separator,
            clear_button,
            separator,
            copy_button,
            separator,
            dump_button,
            separator,
            conf_button,
            separator,
            exit_button,
            separator,
        ]
    ),
    filter=Condition(lambda: True),
)

output_body = ConditionalContainer(
    content=VSplit(
        [
            output_sc,
            conf_menu
        ]
    ),
    filter=Condition(lambda: True),
)

input_body = ConditionalContainer(
    content=VSplit(
        [
            input_sc,
            separator,
            exec_button,
            # separator,
            # clear_button,
            # separator,
            # conf_button,
            # separator,
            # exit_button,
            separator,
        ]
    ),
    filter=Condition(lambda: True),
)

body = FloatContainer(
    content=HSplit(
        [
            title,
            subtitle,
            line,
            menu_bar_body,
            line,
            output_body,
            line,
            input_body,
        ]
    ),
    floats=[
        Float(
            xcursor=True,
            ycursor=True,
            content=CompletionsMenu(max_height=16, scroll_offset=1),
        )
    ],
)


def accept(buff):
    execute_action()


input_sc.accept_handler = accept

# Key bindings
kb = KeyBindings()


@kb.add("c-c")
def _(event):
    event.app.exit()
########################################################################################################################

# The SlashNextOTI Console Application #################################################################################


snx_oti_console = Application(layout=Layout(body, focused_element=input_sc), style=style_set,
                              key_bindings=kb, full_screen=True, mouse_support=True)


def run():
    snx_oti_console.run()

########################################################################################################################

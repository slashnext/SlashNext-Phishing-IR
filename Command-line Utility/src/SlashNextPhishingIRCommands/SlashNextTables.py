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
Created on January 23, 2020

@author: Saadat Abid
"""
import base64
import os

from textwrap import wrap
from terminaltables import DoubleTable

OUT_DIRECTORY = os.getcwd()


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

    url_reputation = DoubleTable(data_list)
    url_reputation.padding_left = 1
    url_reputation.padding_right = 1
    url_reputation.inner_column_border = True
    url_reputation.inner_row_border = True

    for i, data in enumerate(data_list):
        if i > 0:
            wrapped_url = '\n'.join(wrap(data[0], 35))
            wrapped_t = '\n'.join(wrap(data[1], 10))
            wrapped_tn = '\n'.join(wrap(data[4], 12))
            wrapped_tt = '\n'.join(wrap(data[5], 12))
            wrapped_fs = '\n'.join(wrap(data[6], 12))
            wrapped_ls = '\n'.join(wrap(data[7], 12))

            url_reputation.table_data[i][0] = wrapped_url
            url_reputation.table_data[i][1] = wrapped_t
            url_reputation.table_data[i][4] = wrapped_tn
            url_reputation.table_data[i][5] = wrapped_tt
            url_reputation.table_data[i][6] = wrapped_fs
            url_reputation.table_data[i][7] = wrapped_ls

    return normalize_msg + url_reputation.table


def get_url_scan_table(response_list):
    return get_scan_report_table(response_list, source=1)


def get_url_scan_bulk_table(summary, response_list, output_path):
    lookup = summary.get('lookup', None)
    data_list = []
    if lookup:
        header = ['Lookup Details']
        data_list.append(header)
        sub_header = [
            'Total',
            'Malicious',
            'Benign',
            'API Error',
            'Invalid',
            'Live Scan',
        ]
        data_list.append(sub_header)
        data = [
            lookup.get('total_count'),
            lookup.get('malicious_count'),
            lookup.get('benign_count'),
            lookup.get('error_count'),
            lookup.get('invalid_count'),
            lookup.get('submitted_count'),
        ]
        data_list.append(data)

        scan = summary.get('scan', None)
        if scan:
            header = ['Live Scan Details']
            data_list.append(header)
            sub_header = [
                'Total',
                'Malicious',
                'Benign',
                'API Error',
                'Pending Scan',
            ]
            data_list.append(sub_header)
            data = [
                scan.get('total_count'),
                scan.get('malicious_count'),
                scan.get('benign_count'),
                scan.get('error_count'),
                scan.get('pending_count'),
            ]
            data_list.append(data)

    bulk_scan_report = DoubleTable(data_list)
    bulk_scan_report.padding_left = 1
    bulk_scan_report.padding_right = 1
    bulk_scan_report.inner_column_border = True
    bulk_scan_report.inner_row_border = True

    for response in response_list:
        result_table = get_url_scan_table([response])
        with open(output_path + 'final_results.log', 'a+') as fp:
            fp.writelines(result_table + '\n')

    return bulk_scan_report.table


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

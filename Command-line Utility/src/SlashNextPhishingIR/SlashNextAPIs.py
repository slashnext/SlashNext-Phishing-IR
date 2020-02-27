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
import requests


''' GLOBAL VARS '''
HOST_REPUTE_API = '/oti/v1/host/reputation'
URL_SCAN_API = '/oti/v1/url/scan'
URL_SCANSYNC_API = '/oti/v1/url/scansync'
HOST_REPORT_API = '/oti/v1/host/report'
DL_SC_API = '/oti/v1/download/screenshot'
DL_HTML_API = '/oti/v1/download/html'
DL_TEXT_API = '/oti/v1/download/text'
API_QUOTA = '/oti/v1/quota/status'


def snx_api_request(base, endpoint, data, method='POST'):
    """
    Make the HTTP request to SlashNext cloud API endpoint with the given API args.

    :param base: Corresponds to SlashNext cloud Base URL.
    :param endpoint: Corresponds to SlashNext cloud API to be invoked.
    :param data: Parameter dictionary as part of data.
    :param method: HTTP method to be used for API i.e. GET or POST.
    :return: Status of the API execution (error or success) and response of the SlashNext web API in json format.
    """
    if base is None:
        base = ''

    if base.endswith('/'):
        base = base.strip('/')
    url = base + endpoint

    try:
        response = requests.request(method, url=url, data=data, timeout=300)

        # Enable the commented code section below to enable the logging of API calls.
        # with open('./log.txt', 'a+') as file_handle:
        #     file_handle.write(str('\n' + url + '\n' + str(data) + '\n'))

        if response.status_code == 200:
            try:
                json_response = response.json()

                # with open('./log.txt', 'a+') as file_handle:
                #     file_handle.write(str(json_response) + '\n')

                if json_response.get('errorNo') == 0 or json_response.get('errorNo') == 1:
                    return 'Success', json_response
                else:
                    return '{}'.format(json_response.get('errorMsg')), json_response

            except Exception as e:
                return 'API response JSON decoding failed due to {}'.format(str(e)), response

        elif response.status_code == 404:
            return 'Please provide a valid configuration or contact support@slashnext.com', response
        else:
            return 'API response failed due to {}'.format(response.reason), response

    except requests.exceptions.Timeout:
        return 'Looks like the server is taking to long to respond, this can be caused by either poor connectivity ' \
               'or an error with our servers. Please try again in a while', None
    except requests.exceptions.TooManyRedirects:
        return 'Please provide a valid configuration or contact support@slashnext.com', None
    except requests.exceptions.RequestException:
        return 'Please provide a valid configuration or contact support@slashnext.com', None
    except Exception as e:
        return 'API response failed due to {}'.format(str(e)), None



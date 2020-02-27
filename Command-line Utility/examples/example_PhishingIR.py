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
Created on January 16, 2020

Contains an example of the SlashNextPhishingIR usage from SlashNextPhishingIR module.

@author: Saadat Abid
"""
import os
from SlashNextPhishingIR import SlashNextPhishingIR

phishing_ir = SlashNextPhishingIR(os.getcwd())
phishing_ir.set_conf(
    api_key="this_is_a_valid_api_key",
    base_url="https://oti.slashnext.cloud/api"
)

# Checking if the configurations are successfully loaded
pir_status, pir_details = phishing_ir.get_status()
if pir_status == 'ok':
    print('SlashNext cloud configuration are successfully saved and loaded')

    # Checking the connectivity and authentication with SlashNext cloud
    pir_status, pir_details = phishing_ir.test()
    if pir_status == 'ok':
        print('SlashNext cloud configuration are successfully tested and found working')

        # Checking if the action 'slashnext-api-quota' executed successfully
        pir_status, pir_details, response_list = phishing_ir.execute('slashnext-api-quota')
        if pir_status == 'ok':
            print('slashnext-api-quota action execution done and received response = {}'.format(response_list))
        else:
            print('slashnext-api-quota action execution failed due to "{}"'.format(pir_details))

        # Checking if the action 'slashnext-host-reputation' executed successfully
        pir_status, pir_details, response_list = phishing_ir.execute('slashnext-host-reputation host=www.google.com')
        if pir_status == 'ok':
            print('slashnext-host-reputation action execution done and received response = {}'.format(response_list))
        else:
            print('slashnext-host-reputation action execution failed due to "{}"'.format(pir_details))

    else:
        print('SlashNext cloud connectivity failed due to "{}"'.format(pir_details))

else:
    print('SlashNext cloud configuration failed due to "{}"'.format(pir_details))


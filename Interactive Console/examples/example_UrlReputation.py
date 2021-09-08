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
Created on August 5, 2021

Contains an example of the SlashNextUrlReputation usage from SlashNextPhishingIR module.

@author: Saadat Abid
"""
from SlashNextPhishingIR import SlashNextUrlReputation

url_reputation_action = SlashNextUrlReputation(
    api_key="this_is_a_valid_api_key",
    base_url="https://oti.slashnext.cloud/api"
)

action_name = url_reputation_action.name
action_title = url_reputation_action.title
action_description = url_reputation_action.description
action_parameters = url_reputation_action.parameters
action_help = url_reputation_action.help
response_details, response_list = url_reputation_action.execution(url='https://www.google.com/')

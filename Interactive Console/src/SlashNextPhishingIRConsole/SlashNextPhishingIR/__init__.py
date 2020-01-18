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
Created on December 14, 2019

@author: Saadat Abid
"""
from .SlashNextPhishingIR import SlashNextPhishingIR

# Version string
__version__ = "1.0.0"

# Version tuple.
VERSION = tuple(__version__.split("."))


__all__ = [
    "SlashNextPhishingIR",
    "SlashNextApiQuota",
    "SlashNextHostReputation",
    "SlashNextHostReport",
    "SlashNextHostUrls",
    "SlashNextUrlScan",
    "SlashNextUrlScanSync",
    "SlashNextScanReport",
    "SlashNextDownloadScreenshot",
    "SlashNextDownloadHtml",
    "SlashNextDownloadText",
]
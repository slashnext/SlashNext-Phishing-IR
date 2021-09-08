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

# Version string
__version__ = "1.1.0"

# Version tuple.
VERSION = tuple(__version__.split("."))


__all__ = [
    "SlashNextPhishingIR",
    "SlashNextApiQuota",
    "SlashNextHostReputation",
    "SlashNextHostReport",
    "SlashNextHostUrls",
    "SlashNextUrlReputation",
    "SlashNextUrlScan",
    "SlashNextUrlScanSync",
    "SlashNextScanReport",
    "SlashNextDownloadScreenshot",
    "SlashNextDownloadHtml",
    "SlashNextDownloadText",
]

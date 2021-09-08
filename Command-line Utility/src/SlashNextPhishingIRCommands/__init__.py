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
Created on January 22, 2019

@author: Saadat Abid
"""
from .SlashNextCommandApiQuota import SlashNextCommandApiQuota
from .SlashNextCommandHostReputation import SlashNextCommandHostReputation
from .SlashNextCommandHostReport import SlashNextCommandHostReport
from .SlashNextCommandHostUrls import SlashNextCommandHostUrls
from .SlashNextCommandUrlReputation import SlashNextCommandUrlReputation
from .SlashNextCommandUrlScan import SlashNextCommandUrlScan
from .SlashNextCommandUrlScanBulk import SlashNextCommandUrlScanBulk
from .SlashNextCommandUrlScanSync import SlashNextCommandUrlScanSync
from .SlashNextCommandScanReport import SlashNextCommandScanReport
from .SlashNextCommandDownloadScreenshot import SlashNextCommandDownloadScreenshot
from .SlashNextCommandDownloadHtml import SlashNextCommandDownloadHtml
from .SlashNextCommandDownloadText import SlashNextCommandDownloadText


# Version string
__version__ = "1.1.0"

# Version tuple.
VERSION = tuple(__version__.split("."))


__all__ = [
    "SlashNextCommandApiQuota",
    "SlashNextCommandHostReputation",
    "SlashNextCommandHostReport",
    "SlashNextCommandHostUrls",
    "SlashNextCommandUrlReputation",
    "SlashNextCommandUrlScan",
    "SlashNextCommandUrlScanBulk",
    "SlashNextCommandUrlScanSync",
    "SlashNextCommandScanReport",
    "SlashNextCommandDownloadScreenshot",
    "SlashNextCommandDownloadHtml",
    "SlashNextCommandDownloadText",
]

#!/usr/bin/env python
import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), "README.md")) as f:
    long_description = f.read()

setup(
    name="slashnext-phishing-ir-commands",
    author="Saadat Abid",
    author_email="saadat.abid.2540@slashnext.com",
    version="1.0.1",
    url="https://www.slashnext.com",
    description="SlashNext Phishing Incident Response commands to allow users to perform data enrichment.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages("."),
    install_requires=["requests", "terminaltables", "urllib3", "w3lib", "regex"],
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python",
        "Topic :: Security",
    ],
    entry_points='''
        [console_scripts]
        slashnext-api-quota=SlashNextPhishingIRCommands.SlashNextCommandApiQuota:run
        slashnext-host-reputation=SlashNextPhishingIRCommands.SlashNextCommandHostReputation:run
        slashnext-host-report=SlashNextPhishingIRCommands.SlashNextCommandHostReport:run
        slashnext-host-urls=SlashNextPhishingIRCommands.SlashNextCommandHostUrls:run
        slashnext-url-scan=SlashNextPhishingIRCommands.SlashNextCommandUrlScan:run
        slashnext-url-scan-bulk=SlashNextPhishingIRCommands.SlashNextCommandUrlScanBulk:run
        slashnext-url-scan-sync=SlashNextPhishingIRCommands.SlashNextCommandUrlScanSync:run
        slashnext-scan-report=SlashNextPhishingIRCommands.SlashNextCommandScanReport:run
        slashnext-download-screenshot=SlashNextPhishingIRCommands.SlashNextCommandDownloadScreenshot:run
        slashnext-download-html=SlashNextPhishingIRCommands.SlashNextCommandDownloadHtml:run
        slashnext-download-text=SlashNextPhishingIRCommands.SlashNextCommandDownloadText:run
    ''',
)

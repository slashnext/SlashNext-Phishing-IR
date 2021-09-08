#!/usr/bin/env python
import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), "README.md")) as f:
    long_description = f.read()

setup(
    name='slashnext-phishing-ir-console',
    author="Saadat Abid",
    author_email="saadat.abid.2540@slashnext.com",
    version="1.1.0",
    url="https://www.slashnext.com",
    description="SlashNext Phishing Incident Response console to allow users to perform data enrichment.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages("."),
    install_requires=[
        'pyfiglet',
        'terminaltables',
        'prompt_toolkit',
        'requests',
        'pyperclip',
    ],
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
        SlashNextPhishingIRConsole=SlashNextPhishingIRConsole.SlashNextPhishingIRConsole:run
    ''',
)

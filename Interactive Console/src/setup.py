from setuptools import setup

setup(
    name='slashnext-phishing-ir-console',
    version='0.0.1',
    packages=[
        'SlashNextPhishingIRConsole',
        'SlashNextPhishingIRConsole.SlashNextPhishingIR'
    ],
    include_package_data=True,
    install_requires=[
        'pyfiglet',
        'terminaltables',
        'prompt_toolkit',
        'requests',
        'pyperclip',
    ],
    entry_points='''
        [console_scripts]
        SlashNextPhishingIRConsole=SlashNextPhishingIRConsole.SlashNextPhishingIRConsole:run
    ''',
)

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
Created on January 22, 2020

@author: Saadat Abid
"""
from abc import ABCMeta, abstractmethod


class SlashNextCommand(metaclass=ABCMeta):
    """
    This class implements the abstract base class for all SlashNext commands classes.

    Attributes:
        snx_action (object): An instance of SlashNextAction class.
    """
    def __init__(self, snx_action):
        """
        The constructor for command abstract base class.

        :param snx_action: An instance of SlashNextAction class.
        """
        self.__version = f'\nv1.0.0'
        self.__version += f'\nDeveloped by SlashNext, Inc. (support@slashnext.com)\n'

        self.__usage = f'\n{snx_action.description}\n\n'
        self.__usage += f'Usage: {snx_action.name} -a [api_key] -b [base_url]'
        for param in snx_action.parameters:
            self.__usage += f' -{param.get("parameter")[0]} [{param.get("parameter")}]'

        self.__usage += f'\n'
        self.__usage += f' -a   --api_key          Please provide a valid API Key or contact support@slashnext.com\n'
        self.__usage += f' -b   --base_url         Please provide a valid Base URL or contact support@slashnext.com\n'
        for param in snx_action.parameters:
            param_name = param.get("parameter")
            param_desc = param.get("description")
            self.__usage += ' -{0}   --{1:16} {2}\n'.format(param_name[0], param_name, param_desc)

        self.__usage += f' -V   --version          Version of SlashNext phishing IR commands.\n'
        self.__usage += f' -H   --help             Prints this help/usage.\n'
        self.__usage += f'\nDeveloped by SlashNext, Inc. (support@slashnext.com)\n'

    @property
    def usage(self):
        """
        Gets the usage string of the command.

        :return: Usage of the command.
        """
        return self.__usage

    @property
    def version(self):
        """
        Gets the version string of the command.

        :return: Version of the command.
        """
        return self.__version

    @abstractmethod
    def execution(self, argv):
        """
        Executes the command as per given arguments after validation.

        :param argv: Command line parameters given by the user.
        """
        pass

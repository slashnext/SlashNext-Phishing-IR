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
Created on January 21, 2020

@author: Saadat Abid
"""
from abc import ABCMeta, abstractmethod


class SlashNextAction(metaclass=ABCMeta):
    """
    This class implements the abstract base class for all SlashNext actions classes.

    Attributes:
        name (str): Name of the action.
        title (str): Title of the corresponding action output.
        description (str): Description of the action.
        parameters (list): Accepted parameters of the action.
    """
    def __init__(self, name, title, description, parameters):
        """
        The constructor for action abstract base class.

        :param name: Name of the action.
        :param title: Title of the corresponding action output.
        :param description: Description of the action.
        :param parameters: Accepted parameters of the action.
        """
        self.__name = name
        self.__title = title
        self.__description = description
        self.__parameters = parameters
        self.__help = '\nACTION: ' + self.__name + '\n  ' + self.__description + '\n'
        if len(self.__parameters) == 0:
            self.__help += '\nPARAMETERS: None\n'
        else:
            self.__help += '\nPARAMETERS: \n'
            for param in self.__parameters:
                self.__help += '<' + param.get('parameter') + '>\n  ' + param.get('description') + '\n'

    @property
    def name(self):
        """
        Gets the name string of the action.

        :return: Name of the action.
        """
        return self.__name

    @property
    def title(self):
        """
        Gets the output title string of the action.

        :return: Output title of the action.
        """
        return self.__title

    @property
    def description(self):
        """
        Gets the description string of the action which explains what the action do exactly.

        :return: Description of the action.
        """
        return self.__description

    @property
    def parameters(self):
        """
        Gets the list of the parameters required by the action.

        :return: Accepted parameters list.
        """
        return self.__parameters

    @property
    def help(self):
        """
        Gets the help string of action which gives details on how to execute the action.

        :return: Help on the action.
        """
        return self.__help

    @abstractmethod
    def execution(self, **kwargs):
        """
        Executes the action with the given parameters by invoking the required SlashNext OTI API(s).

        :return: State of the action execution (error or success) and the list of full json response(s) from SlashNext
        OTI cloud.
        """
        pass

from burp import IBurpExtender, ITab, IMessageEditorController
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, GridLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.util import ArrayList

import string
import random
import threading
import time
import cgi
import urllib
import re
import sys
import os
import traceback


class ExampleFrame(swing.JFrame, IMessageEditorController):
    def __init__(self, extender, reqRespToView):
        try:
            self._extender = extender
            self._reqRespToView = reqRespToView
            self.callbacks = self._extender._callbacks
            sys.stdout = self.callbacks.getStdout()
            
            # Set up space for save dialogue
            self.savePanel = swing.JPanel()
            self.savePanel.setLayout(BorderLayout())
            self.savePanel.setBorder(swing.BorderFactory.createEmptyBorder(10, 10, 10, 10))

            tabs = swing.JTabbedPane()
            self._requestViewer = self.callbacks.createMessageEditor(self, False)
            self._responseViewer = self.callbacks.createMessageEditor(self, False)
            tabs.addTab("Request", self._requestViewer.getComponent())
            tabs.addTab("Response", self._responseViewer.getComponent())

            self.savePanel.add(tabs)
            self.add(self.savePanel)

            self.setTitle("Request and response viewer")
            self.setSize(1000, 250)
            self.setDefaultCloseOperation(swing.JFrame.DISPOSE_ON_CLOSE)
            self.setLocationRelativeTo(None)
            
            self.callbacks.customizeUiComponent(self)
            self.setVisible(True)
        except Exception as e:
            self._extender.log(e)
            traceback.print_exc()
        return

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    def getHttpService(self):
        return self._reqRespToView["httpservice"]

    def getRequest(self):
        return self._reqRespToView["request"]

    def getResponse(self):
        return self._reqRespToView["response"]
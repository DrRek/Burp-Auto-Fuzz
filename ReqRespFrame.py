from burp import IBurpExtender, ITab, IMessageEditorController
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, GridLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.util import ArrayList
from javax.swing import JSplitPane;

import string
import random
import threading
import time
import cgi
import urllib
import re
import sys
import os


class ReqRespFrame(swing.JFrame, IMessageEditorController):
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

            tabs = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            self._requestViewer = self.callbacks.createMessageEditor(self, False)
            self._responseViewer = self.callbacks.createMessageEditor(self, False)
            tabs.setLeftComponent(self._requestViewer.getComponent())
            tabs.setRightComponent(self._responseViewer.getComponent())

            self._requestViewer.setMessage(self._reqRespToView["reqResp"].getRequest(), True)
            self._responseViewer.setMessage(self._reqRespToView["reqResp"].getResponse(), False)

            self.savePanel.add(tabs)
            self.add(self.savePanel)

            self.setTitle("Request and response viewer")
            self.setSize(1250, 750)
            self.setDefaultCloseOperation(swing.JFrame.DISPOSE_ON_CLOSE)
            self.setLocationRelativeTo(None)
            
            self.callbacks.customizeUiComponent(self)
            self.callbacks.customizeUiComponent(self.savePanel)
            self.callbacks.customizeUiComponent(tabs)
            self.setVisible(True)
        except Exception as e:
            self._extender.log(e, True)

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    def getHttpService(self):
        return self._reqRespToView["reqResp"].getHttpService()

    def getRequest(self):
        return self._reqRespToView["reqResp"].getRequest()

    def getResponse(self):
        return self._reqRespToView["reqResp"].getResponse()
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from java.net import URL
from threading import Lock
import threading


PAYLOADS = ["--", "'"]
ENABLED = True

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Burp auto fuzzer")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._jobs = ArrayList()
        self._lock = Lock()
        
        # main split pane
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        splitpane.setLeftComponent(scrollPane)

        # table of single fuzzing process
        self._singleFuzzingTable = FuzzingTable(self, FuzzingTableModel(self))
        singleFuzzinSscrollPane = JScrollPane(self._singleFuzzingTable)
        splitpane.setRightComponent(singleFuzzinSscrollPane)

        # tabs with request/response viewers
        self._tabs = JTabbedPane()
        self._tabs.addTab("Fuzz", splitpane)
        #tabs.addTab("Options", self._responseViewer.getComponent())
        #self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._tabs)
        callbacks.customizeUiComponent(splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(self._singleFuzzingTable)
        callbacks.customizeUiComponent(singleFuzzinSscrollPane)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Fuzzer"
    
    def getUiComponent(self):
        return self._tabs
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return

        # for now we only plan to use this extension if the request was in scope and is a GET request, this will likely change in future
        analyzedRequest = self._helpers.analyzeRequest(messageInfo)
        if not(analyzedRequest.getMethod() == "GET" and self._callbacks.isInScope(analyzedRequest.getUrl())):
            return
        
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._jobs.size()
        self._jobs.add(FuzzingJob(row, toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), messageInfo, analyzedRequest, self._callbacks))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._jobs.size()
        except:
            return 0

    def getColumnCount(self):
        return 5

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Id"
        if columnIndex == 1:
            return "Tool"
        if columnIndex == 2:
            return "Type"
        if columnIndex == 3:
            return "Status"
        if columnIndex == 4:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._jobs.get(rowIndex)
        if columnIndex == 0:
            return logEntry._id
        if columnIndex == 1:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 2:
            return logEntry._analyzedRequest.getMethod()
        if columnIndex == 3:
            return logEntry._status
        if columnIndex == 4:
            return logEntry._analyzedRequest.getUrl()

        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
        self._extender._singleFuzzingTable.getModel().selectJob(row)        
        JTable.changeSelection(self, row, col, toggle, extend)

class FuzzingTableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender
        self._selectedJob = None

    def getRowCount(self):
        try:
            return self._selectedJob._fuzzingRequests.length
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Id"
        if columnIndex == 1:
            return "parameter"
        if columnIndex == 2:
            return "payload"
        if columnIndex == 3:
            return "status"
        if columnIndex == 4:
            return "length"
        if columnIndex == 5:
            return "time"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        editedRequest = self._selectedJob._fuzzingRequests.get(rowIndex)
        if columnIndex == 0:
            return self._selectedJob._analyzedRequest.getUrl()
        if columnIndex == 1:
            return editedRequest.parameter
        if columnIndex == 2:
            return editedRequest.payload
        if columnIndex == 3:
            return editedRequest.status_code
        if columnIndex == 4:
            return editedRequest.length
        if columnIndex == 5:
            return editedRequest.time
        return ""

    def selectJob(self, row):
        self._selectedJob = self._extender._jobs.get(row)
        self.fireTableDataChanged()

class FuzzingTable(JTable):
    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)
    
    def changeSelection(self, row, col, toggle, extend):        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url

class FuzzingJob:
    STATUS_ADDED = "added"
    STATUS_NOT_TO_START = "not_to_start"
    STATUS_STARTED = "started"
    STATUS_FINISHED = "finished"

    def __init__(self, id1, tool, requestResponse, messageInfo, analyzedRequest, callbacks):
        self._tool = tool
        self._requestResponse = requestResponse
        self._messageInfo = messageInfo
        self._analyzedRequest = analyzedRequest
        self._id = id1
        self._parameters = [] #find out how to do this
        self._fuzzingRequests = []
        self._callbacks = callbacks
        self.initialize()
    
    def initialize(self):
        self._status = FuzzingJob.STATUS_ADDED

        #check if in scope
        for parameter in self._analyzedRequest.getParameters():
            for payload in PAYLOADS:
                newFuzzingRequest = {
                    "parameter": parameter,
                    "payload": payload
                }
                url = str(self._analyzedRequest.getUrl())
                value_start = self._analyzedRequest.getParameters()[0].getValueStart()
                value_end = self._analyzedRequest.getParameters()[0].getValueEnd()
                url = URL(url[0:value_start]+url[value_end:-1])

                headers = self._analyzedRequest.getHeaders()
                bodyOffset = self._analyzedRequest.bodyOffset 

                host = self._messageInfo.getHost()
                port = self._messageInfo.getPort()
                protocol = self._messageInfo.getProtocol()
                protoChoice = True if protocol.lower() == 'https' else False

                # Build the request to be sent
                request = self._callbacks.getHelpers().buildHttpRequest(url)

                # Need to make the HTTP request in new thread to
                # prevent the GUI from locking up while the 
                # request is being made.
                t = threading.Thread(
                    target=self.makeRequest,
                    args=[host, port, protoChoice, request]
                )
                t.daemon = True
                t.start()

                newFuzzingRequest["status_code"] = "response.status_code"
                newFuzzingRequest["length"] = "len(response.content)"

    def makeRequest(self, host, port, protoChoice, request):
        """Makes an HTTP request and writes the response to
        the response text area.
        """
        resp = self._callbacks.makeHttpRequest(
            host,           # string
            port,           # int
            protoChoice,    # bool
            request         # bytes
        )

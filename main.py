from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
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
from threading import Lock
from HistoryTable import HistoryTable
from JobTable import JobTable
from FuzzJob import FuzzJob
from javax.swing import JFrame
from javax.swing import JPanel
from ExampleFrame import ExampleFrame

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        # obtain our output and error streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp auto fuzzer")

        # create the log and a lock on which to synchronize when adding log entries
        self._jobs = ArrayList()
        self._selectedJob = None
        self._lock = Lock()
        
        # main split pane
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of history entries
        self._historyTable = HistoryTable(self)
        historyScrollPane = JScrollPane(self._historyTable)
        splitpane.setLeftComponent(historyScrollPane)

        # table of single fuzzing process
        self._singleFuzzingTable = JobTable(self)
        singleFuzzinScrollPane = JScrollPane(self._singleFuzzingTable)
        splitpane.setRightComponent(singleFuzzinScrollPane)

        # tabs with request/response viewers
        self._tabs = JTabbedPane()
        self._tabs.addTab("Fuzz", splitpane)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._tabs)
        callbacks.customizeUiComponent(splitpane)
        callbacks.customizeUiComponent(self._historyTable)
        callbacks.customizeUiComponent(historyScrollPane)
        callbacks.customizeUiComponent(self._singleFuzzingTable)
        callbacks.customizeUiComponent(singleFuzzinScrollPane)
        
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

        if not self._callbacks.getToolName(toolFlag) == "Proxy":
            return
        
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._jobs.size()
        self._jobs.add(FuzzJob(self, row, toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), messageInfo, analyzedRequest))
        self._historyTable.updateTable(row, row)
        self._lock.release()

    #
    # implements Jobs getter and setter
    #
    def getJobsCount(self):
        try:
            return self._jobs.size()
        except:
            return 0
    
    def getJobByRow(self, rowIndex):
        jobEntry = self._jobs.get(rowIndex)
        return jobEntry

    def selectJobByRow(self, rowIndex):
        self._selectedJob = self.getJobByRow(rowIndex)
        self._singleFuzzingTable.updateTable()

    def getSelectedJob(self):
        return self._selectedJob

    def updateFuzingTableIfShown(self, updatedId):
        if self._selectedJob != None and self._selectedJob.getId() == updatedId:
            self._singleFuzzingTable.updateTable()

    #
    # Util
    #
    def log(self, msg, error=False):
        if error:
            self._stderr.println(msg)
        else:
            self._stdout.println(msg)

    def openRequestResponsePanel(self, obj):
        self.log("asd")
        self.log(obj)

        ExampleFrame(self, obj)

        #self._reqRespToView = obj
#
        #frame = JFrame("Panel Example")    
        # # tabs with request/response viewers
        #tabs = JTabbedPane()
        #requestViewer = self._callbacks.createMessageEditor(self, False)
        #responseViewer = self._callbacks.createMessageEditor(self, False)
        #tabs.addTab("Request", requestViewer.getComponent())
        #tabs.addTab("Response", responseViewer.getComponent()) 
        #frame.add(tabs)
        #self._callbacks.customizeUiComponent(frame)
        #self._callbacks.customizeUiComponent(tabs)
#
        #frame.setVisible(True)

        #requestViewer.setMessage(obj["request"], True)
        #responseViewer.setMessage(obj["response"], False)



from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener, IParameter
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
from ReqRespFrame import ReqRespFrame
import traceback
import Utils

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
        self._errorLock = Lock()
        
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
        if not(self._callbacks.getToolName(toolFlag) == "Proxy" and self._callbacks.isInScope(analyzedRequest.getUrl())):
            return

        # if there are not parameters (all but cookies) to fuz return
        p = analyzedRequest.getParameters()
        if not Utils.hasSomeAllowedTypeParameters(p):
            return
        
        # create a new log entry with the message details
        self._lock.acquire()

        # if I've already tested for it return
        if self.checkIfRequestAlreadyDone(analyzedRequest):
            return
        
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

    def checkIfRequestAlreadyDone(self, request):
        url = str(request.getUrl()).split("?")[0]
        for job in self._jobs:
            if str(job._analyzedRequest.getUrl()).startswith(url):
                p1 = request.getParameters()
                p2 = job._analyzedRequest.getParameters()

                if self.checkIfP1IsContainedInP2(p1, p2):
                    return True
        return False

    def checkIfP1IsContainedInP2(self, ps1, ps2):
        if ps1.size() > ps2.size():
            return False 

        for p1 in ps1:
            found = False
            for p2 in ps2:
                if p1.getName() == p2.getName():
                    found = True
                    break
            if not found:
                return False
        return True

    #
    # Util
    #
    def log(self, msg, error=False):
        if error:
            self._errorLock.acquire()
            self._stderr.println(msg)
            traceback.print_exc()
            self._errorLock.release()
        else:
            self._stdout.println(msg)

    def openRequestResponsePanel(self, obj):
        ReqRespFrame(self, obj)


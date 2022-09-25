import threading
from java.net import URL
from java.util import ArrayList;
from threading import Lock
from burp import IParameter
import Utils

class FuzzJob:
    STATUS_ADDED = "added"
    STATUS_NOT_TO_START = "not_to_start"
    STATUS_STARTED = "started"
    STATUS_FINISHED = "finished"
    STATUS_ERROR = "error"

    def __init__(self, extender, id1, tool, requestResponse, messageInfo, analyzedRequest):
        self._extender = extender
        self._id = id1
        self._tool = tool
        self._requestResponse = requestResponse
        self._messageInfo = messageInfo
        self._analyzedRequest = analyzedRequest
        self._fuzList = ArrayList()
        self._fuzList.add({
            "reqResp": requestResponse,
            "analyzedResp": self._extender._helpers.analyzeResponse(requestResponse.getResponse()),
            "original": True,
            "id": 0
        })
        self._fuzLock = Lock()
        try:
            self.initialize()
        except Exception as e:
            self._status = FuzzJob.STATUS_ERROR
            self._extender.log(self._analyzedRequest.getUrl())
            self._extender.log(self._analyzedRequest.getParameters())
            self._extender.log(e, True)
    
    def initialize(self):
        self._status = FuzzJob.STATUS_STARTED

        #check if in scope
        for parameter in self._analyzedRequest.getParameters():
            if not Utils.isParameterAllowed(parameter):
                continue
            for payload in Utils.PAYLOADS:
                if parameter.getType() == IParameter.PARAM_URL:
                    payload = parameter.getValue()+self._extender._helpers.urlEncode(payload)
                else:
                    payload = parameter.getValue()+payload

                newParameter = self._extender._helpers.buildParameter(parameter.getName(), parameter.getValue()+payload, parameter.getType())
                newRequest = self._extender._helpers.updateParameter(self._messageInfo.getRequest(), newParameter)

                newFuzzingRequest = {
                    "parameter": newParameter,
                    "id": self._fuzList.size()
                }
                self.addNewFuzzingToJob(newFuzzingRequest)

                t = threading.Thread(
                    target=self.makeRequest,
                    args=[newRequest, newFuzzingRequest]
                )
                t.daemon = True
                t.start()

    def makeRequest(self, request, newFuzzingRequest):
        try:
            """Makes an HTTP request and writes the response to
            the response text area.
            """
            reqResp = self._extender._callbacks.makeHttpRequest(self._messageInfo.getHttpService(), request)

            newFuzzingRequest["reqResp"] = reqResp
            newFuzzingRequest["analyzedResp"] = self._extender._helpers.analyzeResponse(reqResp.getResponse())
            self._extender.updateFuzingTableIfShown(self._id)

            if newFuzzingRequest["id"] == self.getFuzLength():
                self._status = FuzzJob.STATUS_FINISHED
                self._extender.updateFuzingTableIfShown(self._id)

        except Exception as e:
            self._extender.log(e, True)

    def getFuzLength(self):
        return self._fuzList.size()
    
    def getFuzByRow(self, row):
        return self._fuzList.get(row)

    def addNewFuzzingToJob(self, fuz):
        self._fuzLock.acquire()
        self._fuzList.add(fuz)
        self._extender.updateFuzingTableIfShown(self._id)
        self._fuzLock.release()

    def getId(self):
        return self._id

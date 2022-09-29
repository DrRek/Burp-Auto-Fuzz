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
                    "id": self._fuzList.size(),
                    "grep": {}
                }
                fuz_req_index = self.addNewFuzzingToJob(newFuzzingRequest)

                self._extender.requestor.addToTheQueue(fuz_req_index, newRequest, self._messageInfo.getHttpService(), self.finalizeJob)

    def finalizeJob(self, fuz_req_index, reqResp):
        try:
            newFuzzingRequest = self._fuzList[fuz_req_index]
            newFuzzingRequest["reqResp"] = reqResp
            newFuzzingRequest["analyzedResp"] = self._extender._helpers.analyzeResponse(reqResp.getResponse())

            lenResponse = len(reqResp.getResponse())
            for toSearch in Utils.WORDS_TO_SEARCH_IN_RESPONSE:
                if self._extender._helpers.indexOf(reqResp.getResponse(), toSearch, False, 0, lenResponse) != -1:
                    newFuzzingRequest["grep"][toSearch] = True

            self._status = FuzzJob.STATUS_FINISHED
            self._extender.updateFuzingTableIfShown(self._id)

        except Exception as e:
            self._extender.log(e, True)

    def getFuzLength(self):
        return self._fuzList.size()
    
    def getFuzByRow(self, row):
        return self._fuzList.get(row)

    def addNewFuzzingToJob(self, fuz):
        with self._fuzLock:
            self._fuzList.add(fuz)
            index = self._fuzList.size()-1
            self._extender.updateFuzingTableIfShown(self._id)
        return index

    def getId(self):
        return self._id

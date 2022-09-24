import threading
from java.net import URL
from java.util import ArrayList;
from threading import Lock

PAYLOADS = ["--", "'"]

class FuzzJob:
    STATUS_ADDED = "added"
    STATUS_NOT_TO_START = "not_to_start"
    STATUS_STARTED = "started"
    STATUS_FINISHED = "finished"

    def __init__(self, extender, id1, tool, requestResponse, messageInfo, analyzedRequest):
        self._extender = extender
        self._id = id1
        self._tool = tool
        self._requestResponse = requestResponse
        self._messageInfo = messageInfo
        self._analyzedRequest = analyzedRequest
        self._fuzList = ArrayList()
        self._fuzLock = Lock()
        self.initialize()
    
    def initialize(self):
        self._status = FuzzJob.STATUS_ADDED

        #check if in scope
        for parameter in self._analyzedRequest.getParameters():
            for payload in PAYLOADS:
                payload = parameter.getValue()+payload

                self._extender.log(parameter.getValue()+" "+payload)

                newFuzzingRequest = {
                    "parameter": parameter.getName(),
                    "payload": payload
                }
                self.addNewFuzzingToJob(newFuzzingRequest)

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
                request = self._extender._callbacks.getHelpers().buildHttpRequest(url)
                newFuzzingRequest["request"] = request

                # Need to make the HTTP request in new thread to
                # prevent the GUI from locking up while the 
                # request is being made.
                t = threading.Thread(
                    target=self.makeRequest,
                    args=[host, port, protoChoice, request, newFuzzingRequest]
                )
                t.daemon = True
                t.start()

    def makeRequest(self, host, port, protoChoice, request, newFuzzingRequest):
        try:
            """Makes an HTTP request and writes the response to
            the response text area.
            """
            resp = self._extender._callbacks.makeHttpRequest(self._messageInfo.getHttpService(), request)

            newFuzzingRequest["httpservice"] = self._messageInfo.getHttpService()
            newFuzzingRequest["response"] = resp
            newFuzzingRequest["analyzedResp"] = self._extender._helpers.analyzeResponse(resp)
            self._extender.updateFuzingTableIfShown(self._id)
            self._extender
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

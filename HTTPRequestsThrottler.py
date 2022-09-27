from threading import Lock
import threading
import Utils
import time

class HTTPRequestsThrottler:
    def __init__(self, extender):
        self.extender = extender
        self.queue = []
        self.qLock = Lock()
        self.threads = []
        self.tLock = Lock()

    def addToTheQueue(self, request, http_service, callback):
        try:
            with self.qLock:
                self.queue.append({
                    "request": request,
                    "http_service": http_service,
                    "callback": callback
                })

                self.startThreadsIfNotRunning()
                self.extender.log("DEBUG 3 is this ever called")
        except Exception as e:
            self.extender.log(e, True)

    # if there are not enough threads running but they can run this function starts them
    def startThreadsIfNotRunning(self):
        try:
            with self.tLock:
                for t in self.threads:
                    if not t.is_alive():
                        self.threads.remove(t)
                if len(self.threads) < Utils.HTTP_MAX_CONCURRENT_REQUEST:
                    t = threading.Thread(
                        target=self.threadWorker,
                        args=[]
                    )
                    t.daemon = True
                    t.start()
            self.extender.log("DEBUG 2 is this ever called")
        except Exception as e:
            self.extender.log(e, True)

    def threadWorker(self):
        try:
            self.qLock.acquire()
            while self.queue:
                item = self.queue.pop()
                self.qLock.release()

                reqResp = self.extender._callbacks.makeHttpRequest(item["http_service"], item["request"])
                item["callback"](reqResp)

                time.sleep(Utils.HTTP_REQUESTS_DELAY/1000)

                self.qLock.acquire()
            self.qLock.release()
            self.extender.log("DEBUG 1 is this ever called")
        except Exception as e:
            self.extender.log(e, True)

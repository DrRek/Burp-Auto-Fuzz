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

    def addToTheQueue(self, request_id, request, http_service, callback):
        try:
            with self.qLock:
                self.queue.append({
                    "id": request_id,
                    "request": request,
                    "http_service": http_service,
                    "callback": callback
                })

                self.startThreadsIfNotRunning()
        except Exception as e:
            self.extender.log(e, True)

    # if there are not enough threads running but they can run this function starts them
    def startThreadsIfNotRunning(self):
        try:
            with self.tLock:
                alive_threads = []
                for t in self.threads:
                    if t.is_alive():
                        alive_threads.append(t)
                self.threads = alive_threads
                if len(self.threads) < Utils.HTTP_MAX_CONCURRENT_REQUEST:
                    t = threading.Thread(
                        target=self.threadWorker,
                        args=[]
                    )
                    t.daemon = True
                    t.start()
                    self.threads.append(t)
        except Exception as e:
            self.extender.log(e, True)

    def threadWorker(self):
        try:
            self.qLock.acquire()
            while self.queue:
                item = self.queue.pop(0)
                self.qLock.release()

                reqResp = self.extender._callbacks.makeHttpRequest(item["http_service"], item["request"])
                item["callback"](item["id"], reqResp)

                time.sleep(Utils.HTTP_REQUESTS_DELAY/1000)

                self.qLock.acquire()
            self.qLock.release()
        except Exception as e:
            self.extender.log(e, True)

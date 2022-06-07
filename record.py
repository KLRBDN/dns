import time

from threading import Thread
from dns import save, load
from dnslib import QTYPE


class Record:
    def __init__(self, name):
        self.name = name
        self.NS = None
        self.A = None
        self.AAAA = None
        self.PTR = None
        self.NSA = None
        self.ttl = 20

    def __hash__(self):
        return hash(self.name)

    def add_record(self, data):
        if data.q.qtype == QTYPE.A:
            self.A = list(map(lambda x: x.rdata, data.rr))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.AAAA:
            self.AAAA = list(map(lambda x: x.rdata, data.rr))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.PTR:
            self.PTR = data.auth[0].rdata
        elif data.q.qtype == QTYPE.NS:
            self.NS = list(map(lambda x: x.rdata, data.rr))
        elif data.q.qtype == QTYPE.NSA:
            self.NSA = list(map(lambda x: x.rdata, data.rr))
        Thread(target=Record.remove_record, args=(self, data.q.qtype, self.ttl)).start()

    def remove_record(self, qtype, ttl):
        time.sleep(ttl)
        if qtype == QTYPE.A:
            self.A = None
            self.NS = None
        elif qtype == QTYPE.AAAA:
            self.AAAA = None
            self.NS = None
        elif qtype == QTYPE.PTR:
            self.PTR = None
        elif qtype == QTYPE.NS:
            self.NS = None
        elif qtype == QTYPE.NSA:
            self.NSA = None
        print('Removed outdated records from cache')
        save()
        load()

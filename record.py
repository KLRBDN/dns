from dnslib import DNSRecord, QTYPE


class Record:
    def __init__(self, name):
        self.name = name
        self.NS = None
        self.A = None
        self.AAAA = None
        self.PTR = None

    def add_record(self, data: DNSRecord):
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
        else:
            pass
        self.remove_record(data.q.qtype)

    def remove_record(self, qtype):
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

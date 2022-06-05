import pickle
from dnslib import *

from record import Record

PORT = 53
HOST = '127.0.0.1'
DNS_HOST = '1.1.1.1'
flag = False


def start_server():
    global flag
    ttl = 20
    save_cache({})
    cache = load_cache()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_server:
            server.bind((HOST, PORT))
            dns_server.connect((DNS_HOST, PORT))
            server.settimeout(5)
            dns_server.settimeout(5)

            print('Starting the server')
            while True:
                try:
                    u_request, u_address = server.recvfrom(1024)
                    u_data = DNSRecord.parse(u_request)
                except TimeoutError:
                    print('Request timeout')
                    continue
                flag = True
                qname = str(u_data.q.qname)
                if qname in cache:
                    rec = cache.get(qname)
                    query = u_data.reply()
                    flag = False
                    if u_data.q.qtype == QTYPE.A and rec.A:
                        for addr in rec.A:
                            query.add_answer(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.A, ttl=ttl,
                                       rdata=A(addr.data)))
                        for ns in rec.NS:
                            query.add_auth(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.NS, ttl=ttl,
                                       rdata=NS(ns.label)))
                    elif u_data.q.qtype == QTYPE.AAAA and rec.AAAA:
                        for addr in rec.AAAA:
                            query.add_answer(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.AAAA, ttl=ttl,
                                       rdata=AAAA(addr.data)))
                        for ns in rec.NS:
                            query.add_auth(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.NS, ttl=ttl,
                                       rdata=NS(ns.label)))
                    elif u_data.q.qtype == QTYPE.PTR and rec.PTR:
                        query.add_auth(
                            dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.SOA, ttl=ttl,
                                   rdata=rec.PTR))
                    elif u_data.q.qtype == QTYPE.NS and rec.NS:
                        for ns in rec.NS:
                            query.add_answer(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.NS, ttl=ttl,
                                       rdata=NS(ns.label)))
                    else:
                        s_packet = send_request(dns_server, u_request)
                        s_data = DNSRecord.parse(s_packet)
                        cache.get(qname).add_record(s_data)
                        server.sendto(s_packet, u_address)
                        print('Added to cache')
                        continue
                if flag:
                    s_packet = send_request(dns_server, u_request)
                    s_data = DNSRecord.parse(s_packet)
                    cache[qname] = Record(qname)
                    cache.get(qname).add_record(s_data)
                    print('Added to cache')
                    server.sendto(s_packet, u_address)
                else:
                    server.sendto(query.pack(), u_address)
                save_cache(cache)
                cache = {}


def send_request(dns_server, packet):
    try:
        dns_server.send(packet)
        request, address = dns_server.recvfrom(1024)
        return request
    except TimeoutError:
        print('Server timeout')
        return


def save_cache(cache):
    with open("cache.pickle", "wb") as file:
        pickle.dump(cache, file)


def load_cache():
    with open("cache.pickle", "rb") as file:
        return pickle.load(file)


def main():
    start_server()


if __name__ == '__main__':
    main()

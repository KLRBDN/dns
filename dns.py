import pickle

import record

from dnslib import *

PORT = 53
host = '127.0.0.1'
dns_host = '8.8.8.8'
cache = {}
cache_name = 'cache.pickle'
to_cache = False
size = 1024


def save():
    with open(cache_name, 'wb') as write_file:
        pickle.dump(cache, write_file)


def load():
    global cache
    with open(cache_name, 'rb') as read_file:
        cache = pickle.load(read_file)


def send_request(server, pack):
    try:
        server.send(pack)
        request, address = server.recvfrom(size)
        return request
    except Exception:
        print('No response from server')
        return


def start_server():
    ttl = 20
    global cache, to_cache
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_server:
            server.bind((host, PORT))
            dns_server.connect((dns_host, PORT))
            server.settimeout(5)
            dns_server.settimeout(5)

            print('Starting the server')

            while True:
                try:
                    u_request, u_address = server.recvfrom(size)
                    u_data = DNSRecord.parse(u_request)
                except Exception:
                    print(f'Request timeout: No requests in {int(server.gettimeout())} seconds')
                    continue
                to_cache = True
                qname = str(u_data.q.qname)
                if qname in cache:
                    rec = cache.get(qname)
                    query = u_data.reply()
                    to_cache = False
                    if u_data.q.qtype == QTYPE.A and rec.A:
                        for addr in rec.A:
                            query.add_answer(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.A, ttl=ttl,
                                       rdata=A(addr.data)))
                        for ns in rec.NS:
                            query.add_auth(dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.NS, ttl=ttl,
                                                  rdata=NS(ns.label)))
                        for e in rec.NSA:
                            ns, ns_a = e
                            if len(ns_a.data) == 4:
                                query.add_ar(dns.RR(rname=ns.label, rclass=u_data.q.qclass, rtype=QTYPE.A, ttl=ttl,
                                                    rdata=A(ns_a.data)))
                            elif len(ns_a.data) == 16:
                                query.add_ar(dns.RR(rname=ns.label, rclass=u_data.q.qclass, rtype=QTYPE.AAAA, ttl=ttl,
                                                    rdata=AAAA(ns_a.data)))
                    elif u_data.q.qtype == QTYPE.AAAA and rec.AAAA:
                        for addr in rec.AAAA:
                            query.add_answer(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.AAAA, ttl=ttl,
                                       rdata=AAAA(addr.data)))
                        for ns in rec.NS:
                            query.add_auth(dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.NS, ttl=ttl,
                                                  rdata=NS(ns.label)))
                        for e in rec.NSA:
                            ns, ns_a = e
                            if len(ns_a.data) == 4:
                                query.add_ar(dns.RR(rname=ns.label, rclass=u_data.q.qclass, rtype=QTYPE.A, ttl=ttl,
                                                    rdata=A(ns_a.data)))
                            elif len(ns_a.data) == 16:
                                query.add_ar(dns.RR(rname=ns.label, rclass=u_data.q.qclass, rtype=QTYPE.AAAA, ttl=ttl,
                                                    rdata=AAAA(ns_a.data)))
                    elif u_data.q.qtype == QTYPE.PTR and rec.PTR:
                        query.add_auth(dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.SOA, ttl=ttl,
                                              rdata=rec.PTR))
                    elif u_data.q.qtype == QTYPE.NS and rec.NS:
                        for ns in rec.NS:
                            query.add_answer(
                                dns.RR(rname=u_data.q.qname, rclass=u_data.q.qclass, rtype=QTYPE.NS, ttl=ttl,
                                       rdata=NS(ns.label)))
                        for e in rec.NSA:
                            ns, ns_a = e
                            if len(ns_a.data) == 4:
                                query.add_ar(dns.RR(rname=ns.label, rclass=u_data.q.qclass, rtype=QTYPE.A, ttl=ttl,
                                                    rdata=A(ns_a.data)))
                            elif len(ns_a.data) == 16:
                                query.add_ar(dns.RR(rname=ns.label, rclass=u_data.q.qclass, rtype=QTYPE.AAAA, ttl=ttl,
                                                    rdata=AAAA(ns_a.data)))
                    else:
                        s_packet = send_request(dns_server, u_request)
                        s_data = DNSRecord.parse(s_packet)
                        cache.get(qname).add_record(s_data)
                        print('Added packet to cache')
                        server.sendto(s_packet, u_address)
                        continue
                if to_cache:
                    s_packet = send_request(dns_server, u_request)
                    s_data = DNSRecord.parse(s_packet)
                    cache[qname] = record.Record(qname)
                    cache.get(qname).add_record(s_data)
                    print('Added packet to cache')
                    server.sendto(s_packet, u_address)
                else:
                    server.sendto(query.pack(), u_address)
                print('Packet was successfully sent')
                save()
                cache = {}


def main():
    start_server()


if __name__ == '__main__':
    main()

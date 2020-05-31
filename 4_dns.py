import socket
import json
import time
from dnslib import DNSRecord, RR


dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind(("127.0.1.1", 53))


def get_info(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, ('8.8.8.8', 53))
    sock.settimeout(2)
    info = sock.recvfrom(512)[0]
    sock.close()
    return info


def find_in_cache(data):
    question = DNSRecord.parse(data).q
    type = question.qtype
    name = str(question.qname)
    cases = {1: "A", 2: "NS", 12: "PTR", 28: "AAAA"}
    type = cases[type]
    if type == 'PTR':
        name = name.replace('.in-addr.arpa.', '')
        name = name.replace('.ip6.arpa.', '')
        name = '.'.join(name.split('.')[::-1])

    key = str(name) + " " + str(type)
    with open('cache.json', 'r') as cache:
        try:
            cache = json.load(cache)
            if key in cache.keys():
                return cache[key], key
        except json.JSONDecodeError:
            return None
    return None


def save_info(info):
    info = DNSRecord.parse(info)
    info = info.auth + info.ar + info.rr
    dict_info = dict()
    current_time = time.time()

    for item in info:
        item = str(item).split()
        if item[3] == 'PTR':
            name = item[0].replace('.in-addr.arpa.', '')
            name = name.replace('.ip6.arpa.', '')
            name = '.'.join(name.split('.')[::-1])
            dict_info[name + " " + item[3]] = []
            continue
        dict_info[item[0] + " " + item[3]] = []
        if item[3] != 'NS':
            dict_info[item[-1] + " " + "PTR"] = []

    for item in info:
        item = str(item).split()
        if item[3] == 'PTR':
            name = item[0].replace(r'.in-addr.arpa.', '')
            name = name.replace(r'.ip6.arpa.', '')
            name = '.'.join(name.split('.')[::-1])
            dict_info[name + " " + item[3]].append((current_time + float(item[1]), item[-1]))
            continue
        dict_info[item[0] + " " + item[3]].append((current_time + float(item[1]), item[-1]))
        if item[3] != 'NS':
            dict_info[(item[-1] + " " + "PTR")].append((current_time + float(item[1]), item[0]))

    with open('cache.json', 'r+') as cache:
        try:
            updated_cache = json.load(cache)
            updated_cache.update(dict_info)
        except json.JSONDecodeError:
            json.dump(dict_info, cache)
            return

    clear_cache_file()
    with open('cache.json', 'w') as cache:
        json.dump(updated_cache, cache)


def check_ttl():
    current_time = time.time()
    deleted_names = []
    with open('cache.json', 'r+') as cache:
        try:
            updated_cache = json.load(cache)
        except json.JSONDecodeError:
            return
        for name in updated_cache:
            for ttl in updated_cache[name]:
                if current_time > ttl[0]:
                    deleted_names.append(name)
        deleted_names = set(deleted_names)
        for deleted_name in deleted_names:
            updated_cache.pop(deleted_name)

    clear_cache_file()
    with open('cache.json', 'w') as cache:
        json.dump(updated_cache, cache)


def clear_cache_file():
    with open('cache.json', 'w') as cache:
        pass


def main():
    while True:
        try:
            data, address = dns_socket.recvfrom(512)
            check_ttl()
            info = find_in_cache(data)
            if info is None:
                info = get_info(data)
                save_info(info)
            else:
                parsed_data = DNSRecord.parse(data)
                name, type = info[1].split()
                for rdata in info[0]:
                    if type == 'A':
                        parsed_data.add_answer(*RR.fromZone("{} 60 {} {}".format(name, 'A', rdata[1])))
                    elif type == 'AAAA':
                        parsed_data.add_answer(*RR.fromZone("{} 60 {} {}".format(name, 'AAAA', rdata[1])))
                    elif type == 'NS':
                        parsed_data.add_answer(*RR.fromZone("{} 60 {} {}".format(name, 'NS', rdata[1])))
                    elif type == 'PTR':
                        parsed_data.add_answer(*RR.fromZone("{} 60 {} {}".format(name, 'PTR', rdata[1])))

                info = parsed_data.pack()

            dns_socket.sendto(info, address)
        # except ConnectionError:
        #     print('Connection Error')
        except KeyError:
            print('Type must be A/AAAA/NS/PTR')
        except socket.timeout:
            print('DNS request timed out.')


if __name__ == '__main__':
    main()

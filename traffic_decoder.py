from scapy.all import *
import re
import json as j


def decode_traffic(inp):
    """
    Parse 1 RCAP(kind of) net traffic string into readable data
    :param inp:
    :return: list of parsed packets
    """
    # Dividing into packets
    packets = inp.split('0242ac19')
    len_trig = False
    packets_new = list()
    for i in range(1, len(packets)):
        packets[i] = '0242ac19' + packets[i]
        if len(packets[i]) < 13:
            len_trig = True
            continue
        if len_trig:
            packets_new.append(packets[i-1] + packets[i])
            len_trig = False

    # print(len(packets_new))
    packet_jsons = list()
    for packet in packets_new:
        # Translate to Ether obj
        res = list()
        for i in range(len(packet)//2):
            ch = packet[i*2] + packet[i*2+1]
            res.append(int(ch, 16))
        res = bytes(res)
        e = Ether(res)
        # DEBUG
        # print(e.show())
        # Find json and ips
        json = re.findall(r'{.*}', e.payload.original.decode(errors='replace'))
        if len(json) == 0:
            continue
        elif len(json) > 2:
            raise Exception('Json length > 2')
        src = e.payload.src
        dst = e.payload.dst

        # DEBUG
        # if src == '134.60.36.67':
        #     1 == 1
        #     pass
        # if src == '36.205.139.159':
        #     1 == 1
        #     pass
        # if src == '73.100.113.76':
        #     1 == 1
        #     pass
        # Map each packet
        parsed_packet = dict()
        parsed_packet['src'] = src
        try:
            parced_json = j.loads(json[0])

            if parced_json['method'] == "eth_sendRawTransaction" or parced_json['method'] == "eth_call":
                parsed_packet['json'] = parced_json
            else:
                continue
        except:
            continue
        packet_jsons.append(parsed_packet)
    # DEBUG
    # [print(x) for x in packet_jsons]
    return packet_jsons

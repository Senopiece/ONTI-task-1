# Etot kod napisan russkimi blyat dlya blyat russkih.
# On nahuyi reshaet zadachu number first ebat

from traffic_decoder import decode_traffic
from collections import defaultdict
from pprint import pprint
import os

from request_segments import *


def find_dataset_filename():
    for filename in os.listdir():
        if filename.startswith('dataset'):
            return filename
    raise Exception("Can't find dataset file")


# load dataset
dataset = []
with open(find_dataset_filename(), 'r') as dataset_file:
    dataset = dataset_file.read().split()


# for all captured traffic print result ip
for captured_traffic in dataset:
    # get all json packages
    traffic = decode_traffic(captured_traffic)

    # split pkgs by senders
    dialogues = defaultdict(list)  # "sender ip": [{json data}, {json data}...]
    for pkg in traffic:
        if 'method' in pkg['json']:
            dialogues[pkg['src']].append(pkg['json'])
        elif 'result' in pkg['json']:
            dialogues[pkg['dst']].append(pkg['json'])

    # find dialogue that satisfies the conditions
    def find():
        ips = ""
        for ip, dialogue in dialogues.items():
            def is_satisfies_the_conditions():
                deployed_more_than_once = False
                has_undefined_request = False
                responces_with_errors = False
                deployed = False
                first_func_requested = False
                second_func_requested = False
                call_func_requested = False

                for json_from_pkg in dialogue:
                    if 'method' in json_from_pkg:
                        if json_from_pkg['method'] == "eth_sendRawTransaction" or json_from_pkg['method'] == "eth_call":
                            try:
                                call_func_requested = json_from_pkg['params'][0]['data'].startswith(
                                    call_func_selector)
                            except:
                                if json_from_pkg['params'][0].startswith(deploy_selector):
                                    if deployed:
                                        deployed_more_than_once = True
                                        break
                                    else:
                                        deployed = True
                                elif json_from_pkg['params'][0].startswith(first_func_selector):
                                    first_func_requested = True
                                elif json_from_pkg['params'][0].startswith(second_func_selector):
                                    second_func_requested = True
                                else:
                                    has_undefined_request = True
                                    break
                    elif 'error' in json_from_pkg:
                        responces_with_errors = True
                        break

                print('\x1b[6;30;43m'+"IP: "+ip+'\x1b[0m')
                print('Check:', deployed_more_than_once,
                      has_undefined_request,
                      responces_with_errors,
                      deployed,
                      first_func_requested,
                      second_func_requested,
                      call_func_requested)
                print('Dialogue:')
                pprint(dialogue)
                print()
                if deployed_more_than_once or has_undefined_request or responces_with_errors:
                    return False
                else:
                    if deployed and first_func_requested and second_func_requested and call_func_requested:
                        return True
                    else:
                        return False

            if is_satisfies_the_conditions():
                ips += ip + " "
        return ips
        #     is_satisfies_the_conditions()
        # return 'lol end'

    result_ips = find()

    # print sender's ip
    print(result_ips)

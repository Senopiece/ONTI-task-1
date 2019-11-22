# Etot kod napisan russkimi blyat dlya blyat russkih.
# On nahuyi reshaet zadachu number first ebat

from traffic_decoder import decode_traffic
from collections import defaultdict
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
        dialogues[pkg['src']].append(pkg['json'])

    # find dialogue that satisfies the conditions
    def find():
        for ip, dialogue in dialogues.items():
            def is_satisfies_the_conditions():
                deployed_more_than_once = False
                deployed = False
                has_undefined_request = False
                first_func_requested = False
                second_func_requested = False
                call_func_requested = False

                for pkg in dialogue:
                    try:
                        call_func_requested = pkg['params'][0]['data'].startswith(
                            call_func_selector)
                    except:
                        if pkg['params'][0].startswith(deploy_selector):
                            if deployed:
                                deployed_more_than_once = True
                            else:
                                deployed = True
                        elif pkg['params'][0].startswith(first_func_selector):
                            first_func_requested = True
                        elif pkg['params'][0].startswith(second_func_selector):
                            second_func_requested = True
                        else:
                            has_undefined_request = True

                if deployed_more_than_once or has_undefined_request:
                    return False
                else:
                    if deployed and first_func_requested and second_func_requested and call_func_requested:
                        return True
                    else:
                        return False

            if is_satisfies_the_conditions():
                return ip
    result_ip = find()

    # print sender's ip
    print(result_ip)

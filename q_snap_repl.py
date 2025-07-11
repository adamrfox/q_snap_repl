#!/usr/bin/python3
import sys
import getopt
import getpass
import requests
import json
import time
import os
import keyring
import subprocess
from datetime import datetime, timezone
from dateutil import tz
import urllib3
urllib3.disable_warnings()
import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    print("Usage goes here!")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def oprint(fp, message):
    if fp:
        fp.write(message + '\n')
    else:
        print(message)
    return
def api_login(qumulo, user, password, RING_SYSTEM):
    in_keyring = True
    headers = {'Content-Type': 'application/json'}
    if not user:
        if RING_SYSTEM.endswith('src'):
            user = input("Source User: ")
        else:
            user = input("Destination User: ")
    if not password:
        password = keyring.get_password(RING_SYSTEM, user)
    if not password:
        in_keyring = False
        if RING_SYSTEM.endswith('src'):
            password = getpass.getpass("Source Password: ")
        else:
            password = getpass.getpass("Destination Password: ")
    payload = {'username': user, 'password': password}
    payload = json.dumps(payload)
    autht = requests.post('https://' + qumulo + '/api/v1/session/login', headers=headers, data=payload,
                              verify=False, timeout=timeout)
    dprint(str(autht.ok))
    auth = json.loads(autht.content.decode('utf-8'))
    dprint(str(auth))
    if autht.ok:
        auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
        if not in_keyring:
            use_ring = input("Put these credentials into keyring? [y/n]: ")
            if use_ring.startswith('y') or use_ring.startswith('Y'):
                keyring.set_password(RING_SYSTEM, user, password)
    else:
        sys.stderr.write("ERROR: " + auth['description'] + '\n')
        exit(2)
    return(auth_headers)

def qumulo_get(addr, api, auth):
    dprint("API_GET: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying..")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT[GET]: retrying..")
            good = False
            time.sleep(5)
    if res.status_code == 200:
        dprint("RESULTS: " + str(res.content))
        results = json.loads(res.content.decode('utf-8'))
        return(results)
    elif res.status_code == 404:
        return("404")
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + "\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)

def get_token_from_file(file):
    with open(file, 'r') as fp:
        tf = fp.read().strip()
    fp.close()
    t_data = json.loads(tf)
    dprint(t_data['bearer_token'])
    return(t_data['bearer_token'])

if __name__ == "__main__":
    DEBUG = False
    default_token_file = ".qfsd_cred"
    timeout = 30
    src_user = ""
    src_password = ""
    dest_user = ""
    dest_password = ""
    src_qumulo = ""
    src_path = ""
    dest_qumulo = ""
    dest_path = ""
    local_src_path = ""
    local_dest_path = ""
    SRC_RING_SYSTEM = "q_snap_repl_src"
    DEST_RING_SYSTEM = "q_snap_repl_dest"
    fp = ""
    outfile = ""
    ofp = ""
    lf = []
    snaps = []


    optlist, args = getopt.getopt(sys.argv[1:],'hDc:f:s:d', ['--help', '--DEBUG', '--creds=', '--token=', '--token-file=',
                                                               '--src-creds', '--dest-creds'])
    for opt, a in optlist:
        if opt in ['-h,', '--help']:
            usage()
        if opt in ['-D', '--DEBUG']:
            DEBUG = True
            dfh = open('debug.out', 'w')
            dfh.close()
        if opt in ['-c', '--creds']:
            if ':' in a:
                (src_user, src_password) = a.split(':')
                (dest_user, dest_password) = a.split(':')
            else:
                src_user = a
                dest_user = a
        if opt in ('-s', '--src-creds'):
            (src_user, src_password) = a.split(':')
        if opt in ('-d', '--dest-creds'):
            (dest_user, dest_password) = a.split(':')

    try:
        (src, dest) = args
    except:
        usage()
# Validate logins on clusters
    (src_qumulo, src_path) = src.split(':')
    (dest_qumulo, dest_path) = dest.split(':')
    src_auth = api_login(src_qumulo, src_user, src_password, SRC_RING_SYSTEM)
    dprint(str(src_auth))
    dest_auth = api_login(dest_qumulo, dest_user, dest_password, DEST_RING_SYSTEM)
    dprint(str(dest_auth))
# Get local paths on client
    res = subprocess.run('df', stdout=subprocess.PIPE, text=True)
    found = False
    for l in res.stdout.splitlines():
        lf = l.split()
        if lf[0] == src:
            local_src_path = lf[-1]
        elif lf[0] == dest:
            local_dest_path = lf[-1]
    dprint("LOCAL_SRC_PATH: " + local_src_path)
    dprint("LOCAL_DEST_PATH: " + local_dest_path)
    if local_src_path == '' or local_dest_path == '':
        sys.stderr.write('Local paths not found.\n')
        usage()
# Get Qumulo filesystem path from export path
    exp = qumulo_get(src_qumulo, '/v2/nfs/exports/', src_auth)
    for e in exp:
        if e['export_path'] == src_path:
            src_path = e['fs_path']
            if not src_path.endswith('/'):
                src_path = src_path + '/'
            break
    dprint("Q_SRC_PATH: " + src_path)
    exp = qumulo_get(dest_qumulo, '/v2/nfs/exports/', dest_auth)
    for e in exp:
        if e['export_path'] == dest_path:
            dest_path = e['fs_path']
            break
    dprint("Q_DEST_PATH: " + dest_path)
# Get snapshots for source path
    src_ss = qumulo_get(src_qumulo, '/v4/snapshots/status/', src_auth)
    for se in src_ss['entries']:
        if se['source_file_path'] == src_path:
            print('MATCH')
            snaps.append({'id': se['id'], 'name': se['name'], 'timestamp': se['timestamp'], 'expiration': se['expiration']})
    pp.pprint(snaps)
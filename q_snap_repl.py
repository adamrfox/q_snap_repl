#!/usr/bin/python3
import sys
import getopt
import getpass
import requests
import json
import time
import os
import keyring
import keyring.backend
# from keyrings.alt.file import PlaintextKeyring
# keyring.set_keyring(PlaintextKeyring())
import subprocess
from datetime import datetime, timezone
from dateutil import tz
import urllib
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
        if WINDOWS and drive:
            subprocess.run(['net', 'use', '/d', drive])
        exit(3)

def qumulo_post(addr, api, body, auth):
    dprint("API_POST: " + api + " : " + str(body))
    good = False
    while not good:
        good = True
        try:
            res = requests.post('https://' + addr + '/api' + api, headers=auth, data=body, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying....")
            time.sleep(5)
            good = False
    results = json.loads(res.content.decode('utf-8'))
    if res.status_code == 200:
        return (results)
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + '\n')
        if WINDOWS and drive:
            subprocess.run(['net', 'use', '/d', drive])
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
    repl_cmd = 'rsync -av --delete'
    SNAP_LIST = False
    LOGGING = False
    snap_id_list = []
    WINDOWS = False
    rb_threads = 8
    drive = ""


    optlist, args = getopt.getopt(sys.argv[1:],'hDlc:f:s:d:r:i:t:', ['--help', '--DEBUG', '--creds=', '--logging'
                                                               '--src-creds=', '--dest-creds=', '--repl_cmd=', '--ids=,'
                                                                '--threads='])
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
        if opt in ('-r', '--repl_cmd'):
            repl_cmd = a
        if opt in ('-i', '--id-list'):
            SNAP_LIST = True
            snap_id_list = a.split(',')
        if opt in ('-t', '--threads'):
            rb_threads = int(a)
        if opt in ('-l', '--logging'):
            LOGGING = True

    try:
        (src, dest) = args
    except:
        usage()
# Validate logins on clusters
    if src.startswith('\\'):
        WINDOWS = True
        sf = src.split('\\')
        src_qumulo = sf[2]
        src_path = sf[3]
        df = dest.split('\\')
        dest_qumulo = df[2]
        dest_path = df[3]
        repl_cmd = "robocopy /E /MT:" + str(rb_threads) + " /DCOPY:DAT /COPY:DATSO /R:1 /W:1"
    else:
        (src_qumulo, src_path) = src.split(':')
        (dest_qumulo, dest_path) = dest.split(':')
    src_auth = api_login(src_qumulo, src_user, src_password, SRC_RING_SYSTEM)
    dprint(str(src_auth))
    dest_auth = api_login(dest_qumulo, dest_user, dest_password, DEST_RING_SYSTEM)
    dprint(str(dest_auth))
    if WINDOWS:
        share_data = qumulo_get(dest_qumulo, '/v2/smb/shares/' + dest_path, dest_auth)
        if share_data == "404":
            print("GOT 404 in share_data")
            exit(2)
        print(share_data['fs_path'])
        dest_path = share_data['fs_path']
    get_dest_path = qumulo_get(dest_qumulo, '/v1/files/' + urllib.parse.quote(dest_path, safe='') + '/info/attributes',
                               dest_auth)
    if get_dest_path == "404":
        print('GOT 404 in dir_info')
        exit(2)
    dprint(str(get_dest_path))
    dest_id = get_dest_path['id']
# Get local paths on client
    if WINDOWS:
        lf = src.split('\\')
        local_src_path = lf[-1]
        lf = dest.split('\\')
        local_dest_path = lf[-1]
    else:
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
    if WINDOWS:
        exp = qumulo_get(src_qumulo, '/v2/smb/shares/' + local_src_path, src_auth)
        if exp == "404":
            print("src share got 404")
            exit(2)
        src_path = exp['fs_path']
    else:
        exp = qumulo_get(src_qumulo, '/v2/nfs/exports/', src_auth)
        for e in exp:
            if e['export_path'] == src_path:
                src_path = e['fs_path']
                break
    if not src_path.endswith('/'):
        src_path = src_path + '/'
    dprint("Q_SRC_PATH: " + src_path)
    if WINDOWS:
        exp = qumulo_get(dest_qumulo, '/v2/smb/shares/' + local_dest_path, dest_auth)
        if exp == "404":
            print("dest share got 404")
            exit(2)
        dest_path = exp['fs_path']
    else:
        exp = qumulo_get(dest_qumulo, '/v2/nfs/exports/', dest_auth)
        for e in exp:
            if e['export_path'] == dest_path:
                dest_path = e['fs_path']
                break
    dprint("Q_DEST_PATH: " + dest_path)
# Get snapshots for source path
    src_ss = qumulo_get(src_qumulo, '/v4/snapshots/status/', src_auth)
    for se in src_ss['entries']:
        if not SNAP_LIST:
            if se['source_file_path'] == src_path:
                if '_replication_' in se['name'] and se['expiration'] == '':
                    continue
                snaps.append({'id': se['id'], 'name': se['name'], 'timestamp': se['timestamp'], 'expiration': se['expiration']})
        elif str(se['id']) in snap_id_list:
            snaps.append(
                    {'id': se['id'], 'name': se['name'], 'timestamp': se['timestamp'], 'expiration': se['expiration']})

    dprint("SNAP_LIST: "+ str(snaps))
    if WINDOWS:
        wm = subprocess.run(['net', 'use', '*', src ], capture_output=True, text=True)
        dprint("WIN_MOUNT: " + str(wm))
        if not wm.stdout:
            sys.stderr.write('WIN_MOUNT failed: ' + wm.stderr)
            exit(3)
        wmf = wm.stdout.split()
        drive = wmf[1]
        dprint("DRIVE: " + drive)
# Loop on snapshots
    repl_cmd_l = repl_cmd.split()
    if not WINDOWS:
        repl_cmd_l.append('.')
        repl_cmd_l.append(local_dest_path)
        dprint("REPL_CMD: " + str(repl_cmd_l))
    for snap in snaps:
        print("Replicating " + snap['name'])
        if WINDOWS:
            repl_cmd_win = repl_cmd_l.copy()
            repl_cmd_win.append(drive + '\\.snapshot\\' + snap['name'])
            repl_cmd_win.append(dest)
            dprint("REP_CMD: " + str(repl_cmd_win))
            win_repl = subprocess.run(repl_cmd_win, capture_output=True, text=True)
            print("REPL_OUT:")
            print(win_repl.stdout)
        else:
            if LOGGING:
                with open('repl_log_' + str(snap['id']) + '.txt', 'w') as file:
                    subprocess.run(repl_cmd_l, cwd=local_src_path + '/.snapshot/' + snap['name'], stdout=file,
                                   stderr=subprocess.STDOUT)
                file.close()
            else:
                subprocess.run(repl_cmd_l, cwd=local_src_path + '/.snapshot/' + snap['name'])
        snap_f = snap['name'].split('_')
        snap_f.pop(0)
        snap_strip = '_'.join(snap_f)
        body = json.dumps({'name_suffix': snap_strip, 'expiration': snap['expiration'], 'source_file_id': dest_id})
        print("Creating snapshot on target")
        qumulo_post(dest_qumulo, '/v3/snapshots/', body, dest_auth)
# Final Replication (active filesystem)
    print("Final Replication")
    repl_cmd_l = []
    repl_cmd_l = repl_cmd.split()
    if not WINDOWS:
        repl_cmd_l.append('--exclude')
        repl_cmd_l.append("'.snapshot'")
        repl_cmd_l.append('.')
        repl_cmd_l.append(local_dest_path)
        dprint("FINAL REPL_CMD: " + str(repl_cmd_l))
        if LOGGING:
            with open ('repl_log_final.txt', 'w') as file:
                subprocess.run(repl_cmd_l, cwd=local_src_path, stdout=file, stderr=subprocess.STDOUT)
                file.close()
        subprocess.run(repl_cmd_l, cwd=local_src_path)
    else:
        repl_cmd_win = repl_cmd_l.copy()
        repl_cmd_win.append(drive)
        repl_cmd_win.append(dest)
        repl_cmd_win.append('/XD')
        repl_cmd_win.append('.snapshot')
        dprint("FINAL_REPL_CMD: " + str(repl_cmd_win))
        win_repl = subprocess.run(repl_cmd_win, capture_output=True, text=True)
        print("DRIVE: "+ drive)
        subprocess.run(['net', 'use', '/d', drive])




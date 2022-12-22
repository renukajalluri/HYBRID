
import pickle
from collections import Counter
from flask import Flask, render_template, request, url_for

import numpy as np
from flask import jsonify
# initiate flask
app = Flask(__name__)


with open('rfc.pkl', 'rb') as file:
    rfc = pickle.load(file)

with open('dtc.pkl', 'rb') as file:
    dtc = pickle.load(file)


with open('xgbc.pkl', 'rb') as file:
    xgbc = pickle.load(file)


with open('svmp.pkl', 'rb') as file:
    svmp = pickle.load(file)

with open('min_max_scalerf.pkl', 'rb') as file:
    scaler = pickle.load(file)

# flag ={'SF': 1, 'S1': 2, 'REJ': 3, 'S2': 4, 'S0': 5, 'S3': 6, 'RSTO': 7, 'RSTR': 8,
# 'RSTOS0': 9, 'OTH': 10, 'SH': 11}


service = {'http': 1, 'smtp': 2, 'finger': 3, 'domain_u': 4, 'auth': 5, 'telnet': 6,
           'ftp': 7, 'eco_i': 8, 'ntp_u': 9, 'ecr_i': 10, 'other': 11, 'private': 12,
           'pop_3': 13, 'ftp_data': 14, 'rje': 15, 'time': 16, 'mtp': 17, 'link': 18,
           'remote_job': 19, 'gopher': 20, 'ssh': 21, 'name': 22, 'whois': 23,
           'domain': 24, 'login': 25, 'imap4': 26, 'daytime': 27, 'ctf': 28, 'nntp':
           29, 'shell': 30, 'IRC': 31, 'nnsp': 32, 'http_443': 33, 'exec': 34,
           'printer': 35, 'efs': 36, 'courier': 37, 'uucp': 38, 'klogin': 39, 'kshell':
           40, 'echo': 41, 'discard': 42, 'systat': 43, 'supdup': 44, 'iso_tsap':
           45, 'hostnames': 46, 'csnet_ns': 47, 'pop_2': 48, 'sunrpc': 49,
           'uucp_path': 50, 'netbios_ns': 51, 'netbios_ssn': 52,
           'netbios_dgm': 53, 'sql_net': 55, 'vmnet': 56, 'bgp': 57, 'Z39_50':
           58, 'ldap': 59, 'netstat': 60, 'urh_i': 61, 'X11': 62, 'urp_i': 63,
           'pm_dump': 64, 'tftp_u': 65, 'tim_i': 66, 'red_i': 67}

protocol_type = {'tcp': 1, 'udp': 2, 'icmp': 3}

f = ['src_bytes', 'count', 'service', 'dst_bytes', 'dst_host_same_src_port_rate', 'srv_count',
     'dst_host_count', 'protocol_type', 'dst_host_srv_diff_host_rate', 'dst_host_srv_count']

attack = {1: 'attack',  0: 'normal'}


@app.route('/pred', methods=['POST'])
def home():

    if request.method == 'POST':
        data = request.get_json()

        l = data["data"]
        print(l)
        l['protocol_type'] = protocol_type[l['protocol_type']]
        l['service'] = service[l['service']]

        Inp = []
        for x in f:
            Inp.append(float(l[x]))

        print(Inp)

        X = scaler.transform([Inp])

        X_test = X
        y_pred1 = dtc.predict(X_test)
        y_pred2 = rfc.predict(X_test)
        y_pred3 = xgbc.predict(X_test)
        y_pred4 = svmp.predict(X_test)

        data = Counter([y_pred1[0], y_pred2[0], y_pred3[0], y_pred4[0]])

        out = data.most_common(1)[0][0]

        d = {"Prediction": attack[out]}

    return jsonify(d)


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)

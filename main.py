from kmeans.kmeans_nsl import KMeansNSL
from kmeans.packet import Packet
from flask import Flask, render_template
import flatbuffers
from flask import request
from flask_sockets import Sockets
import json
import time
import random

normal = 0
anomaly = 0

app = Flask(__name__)
sockets = Sockets(app)
kmean = KMeansNSL()


@sockets.route('/ws')
def web_socket(ws):
    while not ws.closed:
        message = ws.receive()
        if (message == "statistic"):
            ws.send(json.dumps({
                "normal": normal,
                "anomaly": anomaly
            }))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict_packet():
    raw_data = request.get_data()
    data = Packet.GetRootAsPacket(raw_data, 0)
    packet = {
        "duration": data.Duration(),
        "protocol_type": data.ProtocolType(),
        "service": data.Service(),
        "flag": data.Flag(),
        "src_bytes": data.SrcBytes(),
        "dst_bytes": data.DstBytes(),
        "land": data.Land(),
        "wrong_fragment": data.WrongFragment(),
        "urgent": data.Urgent(),
        "hot": data.Hot(),
        "num_failed_logins": data.NumFailedLogins(),
        "logged_in": data.LoggedIn(),
        "num_compromised": data.NumCompromised(),
        "root_shell": data.RootShell(),
        "su_attempted": data.SuAttempted(),
        "num_root": data.NumRoot(),
        "num_file_creations": data.NumFileCreations(),
        "num_shells": data.NumShells(),
        "num_access_files": data.NumAccessFiles(),
        "num_outbound_cmds": data.NumOutboundCmds(),
        "is_host_login": data.IsHostLogin(),
        "is_guest_login": data.IsGuestLogin(),
        "count": data.Count(),
        "srv_count": data.SrvCount(),
        "serror_rate": data.SerrorRate(),
        "srv_serror_rate": data.SrvSerrorRate(),
        "rerror_rate": data.RerrorRate(),
        "srv_rerror_rate": data.SrvRerrorRate(),
        "same_srv_rate": data.SameSrvRate(),
        "diff_srv_rate": data.DiffSrvRate(),
        "srv_diff_host_rate": data.SrvDiffHostRate(),
        "dst_host_count": data.DstHostSrvCount(),
        "dst_host_srv_count": data.DstHostSrvCount(),
        "dst_host_same_srv_rate": data.DstHostSameSrvRate(),
        "dst_host_diff_srv_rate": data.DstHostDiffSrvRate(),
        "dst_host_same_src_port_rate": data.DstHostSameSrcPortRate(),
        "dst_host_srv_diff_host_rate": data.DstHostSrvDiffHostRate(),
        "dst_host_serror_rate": data.DstHostSerrorRate(),
        "dst_host_srv_serror_rate": data.DstHostSrvSerrorRate(),
        "dst_host_rerror_rate": data.DstHostRerrorRate(),
        "dst_host_srv_rerror_rate": data.DstHostSrvRerrorRate()
    }
    result = kmean.predict(packet)
    if (result != "normal"):
        global anomaly
        anomaly = anomaly + 1
    else:
        global normal
        normal = normal + 1
    return result


if __name__ == '__main__':
    kmean.load_training_data('datasets/KDDTrain+.csv')
    kmean.train_clf()

    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    server = pywsgi.WSGIServer(('', 5000), app, handler_class=WebSocketHandler)
    server.serve_forever()

# # 0,tcp,private,REJ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,229,10,0,0,1,1,0.04,0.06,0,255,10,0.04,0.06,0,0,0,0,1,1,neptune,21

    # packet = {
    #     "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "REJ", "src_bytes": 0,
    #     "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 229, "srv_count": 10, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 1, "srv_rerror_rate": 1, "same_srv_rate": 0.04,
    #     "diff_srv_rate": 0.06, "srv_diff_host_rate": 0, "dst_host_count": 255, "dst_host_srv_count": 10,
    #     "dst_host_same_srv_rate": 0.04, "dst_host_diff_srv_rate": 0.06, "dst_host_same_src_port_rate": 0,
    #     "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
    #     "dst_host_rerror_rate": 1, "dst_host_srv_rerror_rate": 1
    # }

    # print kmean.predict(packet)

    # # 2,tcp,ftp_data,SF,12983,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,134,86,0.61,0.04,0.61,0.02,0,0,0,0,normal,21
    # packet = {
    #     "duration": 2, "protocol_type": "tcp", "service": "ftp_data", "flag": "SF", "src_bytes": 12983,
    #     "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 1,
    #     "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 134, "dst_host_srv_count": 86,
    #     "dst_host_same_srv_rate": 0.61, "dst_host_diff_srv_rate": 0.04, "dst_host_same_src_port_rate": 0.61,
    #     "dst_host_srv_diff_host_rate": 0.02, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
    #     "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    # }
    # print kmean.predict(packet)

    # # 0,tcp,pop_3,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,1,0,0,255,87,0.34,0.01,0.01,0,1,1,0,0,mscan,18
    # packet = {
    #     "duration": 0, "protocol_type": "tcp", "service": "pop3", "flag": "S0", "src_bytes": 0,
    #     "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1, "serror_rate": 1,
    #     "srv_serror_rate": 1, "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 1,
    #     "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 255, "dst_host_srv_count": 87,
    #     "dst_host_same_srv_rate": 0.34, "dst_host_diff_srv_rate": 0.01, "dst_host_same_src_port_rate": 0.01,
    #     "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 1, "dst_host_srv_serror_rate": 1,
    #     "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    # }
    # print kmean.predict(packet)

    # # 0,udp,private,SF,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,133,1,0,0,0,0,0.01,0.71,0,255,1,0,0.86,1,0,0,0,0,0,satan,18
    # packet = {
    #     "duration": 0, "protocol_type": "udp", "service": "private", "flag": "SF", "src_bytes": 1,
    #     "dst_bytes": 1, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 133, "srv_count": 1, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 0.01,
    #     "diff_srv_rate": 0.71, "srv_diff_host_rate": 0, "dst_host_count": 255, "dst_host_srv_count": 1,
    #     "dst_host_same_srv_rate": 0, "dst_host_diff_srv_rate": 0.86, "dst_host_same_src_port_rate": 1,
    #     "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
    #     "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    # }
    # print kmean.predict(packet)

    # # 0,tcp,http,SF,225,1148,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,11,11,0,0,0,0,1,0,0,255,255,1,0,0,0,0,0,0,0,normal,21
    # packet = {
    #     "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "src_bytes": 225,
    #     "dst_bytes": 1148, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 1, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 11, "srv_count": 11, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 1,
    #     "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 255, "dst_host_srv_count": 255,
    #     "dst_host_same_srv_rate": 1, "dst_host_diff_srv_rate": 0, "dst_host_same_src_port_rate": 0,
    #     "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
    #     "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    # }
    # print kmean.predict(packet)

    # # 280,tcp,ftp_data,SF,283618,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,2,0,0,0,0,1,0,0,6,20,1,0,1,0.15,0,0.05,0,0,warezmaster,16
    # packet = {
    #     "duration": 280, "protocol_type": "tcp", "service": "ftp_data", "flag": "SF", "src_bytes": 283618,
    #     "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 2, "srv_count": 2, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 1,
    #     "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 6, "dst_host_srv_count": 20,
    #     "dst_host_same_srv_rate": 1, "dst_host_diff_srv_rate": 0, "dst_host_same_src_port_rate": 1,
    #     "dst_host_srv_diff_host_rate": 0.15, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0.05,
    #     "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    # }
    # print kmean.predict(packet)

    # # 0,icmp,ecr_i,SF,1032,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,511,511,0,0,0,0,1,0,0,255,84,0.33,0.02,0.33,0,0,0,0,0,smurf,19
    # packet = {
    #     "duration": 0, "protocol_type": "icmp", "service": "ecr_i", "flag": "SF", "src_bytes": 1032,
    #     "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 511, "srv_count": 511, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 1,
    #     "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 255, "dst_host_srv_count": 84,
    #     "dst_host_same_srv_rate": 0.33, "dst_host_diff_srv_rate": 0.02, "dst_host_same_src_port_rate": 0.33,
    #     "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
    #     "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    # }
    # print kmean.predict(packet)

    # # 0,tcp,private,RSTR,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,1,1,0,0,74,1,0.01,0.78,0.78,0,0,0,0.78,1,portsweep,15
    # packet = {
    #     "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "RSTR", "src_bytes": 0,
    #     "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 1, "srv_rerror_rate": 1, "same_srv_rate": 1,
    #     "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 74, "dst_host_srv_count": 1,
    #     "dst_host_same_srv_rate": 0.01, "dst_host_diff_srv_rate": 0.78, "dst_host_same_src_port_rate": 0.78,
    #     "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
    #     "dst_host_rerror_rate": 0.78, "dst_host_srv_rerror_rate": 1
    # }
    # print kmean.predict(packet)

    # # 8100,tcp,telnet,SF,0,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,255,84,0.33,0.02,0,0,0.66,0.52,0.01,0.02,processtable,17
    # packet = {
    #     "duration": 8100, "protocol_type": "tcp", "service": "telnet", "flag": "SF", "src_bytes": 0,
    #     "dst_bytes": 15, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
    #     "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    #     "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    #     "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1, "serror_rate": 0,
    #     "srv_serror_rate": 0, "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 1,
    #     "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 255, "dst_host_srv_count": 84,
    #     "dst_host_same_srv_rate": 0.33, "dst_host_diff_srv_rate": 0.02, "dst_host_same_src_port_rate": 0,
    #     "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0.66, "dst_host_srv_serror_rate": 0.52,
    #     "dst_host_rerror_rate": 0.01, "dst_host_srv_rerror_rate": 0.02
    # }
    # print kmean.predict(packet)

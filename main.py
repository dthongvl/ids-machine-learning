from kmeans.kmeans_nsl import KMeansNSL
from kmeans.Packet import Packet
from flask import Flask
import flatbuffers
from flask import request

app = Flask(__name__)
kmean = KMeansNSL()


@app.route('/')
def index():
    return 'Hi!'


@app.route('/predict', methods=['POST'])
def predict_package():
    # raw_packet = bytearray(request.form.get('packet'), 'latin-1')
    # packet = Packet.GetRootAsPacket(raw_packet, 0)
    # 0,tcp,private,REJ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,229,10,0,0,1,1,0.04,0.06,0,255,10,0.04,0.06,0,0,0,0,1,1,neptune,21

    packet = {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "REJ", "src_bytes": 0,
        "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
        "logged_in": 0, "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 229, "srv_count": 10, "serror_rate": 0,
        "srv_serror_rate": 0, "rerror_rate": 1, "srv_rerror_rate": 1, "same_srv_rate": 0.04,
        "diff_srv_rate": 0.06, "srv_diff_host_rate": 0, "dst_host_count": 255, "dst_host_srv_count": 10,
        "dst_host_same_srv_rate": 0.04, "dst_host_diff_srv_rate": 0.06, "dst_host_same_src_port_rate": 0,
        "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 1, "dst_host_srv_rerror_rate": 1
    }

    # 2,tcp,ftp_data,SF,12983,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,134,86,0.61,0.04,0.61,0.02,0,0,0,0,normal,21
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
    print kmean.predict(packet)
    return 'hii'


if __name__ == '__main__':
    kmean.load_training_data('datasets/KDDTrain+.csv')
    kmean.train_clf()

    kmean.load_test_data('datasets/KDDTest+.csv')
    kmean.evaluate_results()
    app.run()

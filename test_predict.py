import flatbuffers
from kmeans.packet import *
import requests
import pandas as pd

COL_NAMES = ["duration", "protocol_type", "service", "flag", "src_bytes",
             "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
             "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
             "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
             "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
             "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
             "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
             "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
             "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "labels"]


def test_predict():
    df = pd.read_csv('datasets/KDDTest+.csv', names=COL_NAMES,
                     index_col=False, nrows=200)
    correct = 0
    for index, row in df.iterrows():
        builder = flatbuffers.Builder(1024)
        protocol_type = builder.CreateString(row['protocol_type'])
        service = builder.CreateString(row['service'])
        flag = builder.CreateString(row['flag'])

        PacketStart(builder)
        PacketAddDuration(builder, row['duration'])
        PacketAddProtocolType(builder, protocol_type)
        PacketAddService(builder, service)
        PacketAddFlag(builder, flag)
        PacketAddSrcBytes(builder, row['src_bytes'])
        PacketAddDstBytes(builder, row['dst_bytes'])
        PacketAddLand(builder, row['land'])
        PacketAddWrongFragment(builder, row['wrong_fragment'])
        PacketAddUrgent(builder, row['urgent'])
        PacketAddHot(builder, row['hot'])
        PacketAddNumFailedLogins(builder, row['num_failed_logins'])
        PacketAddLoggedIn(builder, row['logged_in'])
        PacketAddNumCompromised(builder, row['num_compromised'])
        PacketAddRootShell(builder, row['root_shell'])
        PacketAddSuAttempted(builder, row['su_attempted'])
        PacketAddNumRoot(builder, row['num_root'])
        PacketAddNumFileCreations(builder, row['num_file_creations'])
        PacketAddNumShells(builder, row['num_shells'])
        PacketAddNumAccessFiles(builder, row['num_access_files'])
        PacketAddNumOutboundCmds(builder, row['num_outbound_cmds'])
        PacketAddIsHostLogin(builder, row['is_host_login'])
        PacketAddIsGuestLogin(builder, row['is_guest_login'])
        PacketAddCount(builder, row['count'])
        PacketAddSrvCount(builder, row['srv_count'])
        PacketAddSerrorRate(builder, row['serror_rate'])
        PacketAddSrvSerrorRate(builder, row['srv_serror_rate'])
        PacketAddRerrorRate(builder, row['rerror_rate'])
        PacketAddSrvRerrorRate(builder, row['srv_rerror_rate'])
        PacketAddSameSrvRate(builder, row['same_srv_rate'])
        PacketAddDiffSrvRate(builder, row['diff_srv_rate'])
        PacketAddSrvDiffHostRate(builder, row['srv_diff_host_rate'])
        PacketAddDstHostCount(builder, row['dst_host_count'])
        PacketAddDstHostSrvCount(builder, row['dst_host_srv_count'])
        PacketAddDstHostSameSrvRate(builder, row['dst_host_same_srv_rate'])
        PacketAddDstHostDiffSrvRate(builder, row['dst_host_diff_srv_rate'])
        PacketAddDstHostSameSrcPortRate(
            builder, row['dst_host_same_src_port_rate'])
        PacketAddDstHostSrvDiffHostRate(
            builder, row['dst_host_srv_diff_host_rate'])
        PacketAddDstHostSerrorRate(builder, row['dst_host_serror_rate'])
        PacketAddDstHostSrvSerrorRate(builder, row['dst_host_srv_serror_rate'])
        PacketAddDstHostRerrorRate(builder, row['dst_host_rerror_rate'])
        PacketAddDstHostSrvRerrorRate(builder, row['dst_host_srv_rerror_rate'])

        orc = PacketEnd(builder)
        builder.Finish(orc)
        buf = builder.Output()
        data = buf.decode('latin-1')

        r = requests.post('http://localhost:5000/predict', data={'data': data})
        if r.text.strip() == 'normal' and row['labels'].strip() == 'normal':
            correct = correct + 1
        if r.text.strip() == 'anomaly' and row['labels'].strip() != 'normal':
            correct = correct + 1
    accuracy = (correct * 1.0)/200*100
    assert accuracy > 74


# if __name__ == '__main__':
#     for col_name in COL_NAMES:
#         col_name_split = [x.capitalize() for x in col_name.split('_')]
#         print 'PacketAdd' + ''.join(col_name_split) + "(builder, row['" + col_name + "'])"

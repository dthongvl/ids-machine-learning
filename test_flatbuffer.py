import flatbuffers
from kmeans.Packet import Packet
import requests


def test_flatbuffer():
    builder = flatbuffers.Builder(1024)
    Packet.PacketStart(builder)
    Packet.PacketAddDuration(builder, 123)
    orc = Packet.PacketEnd(builder)
    builder.Finish(orc)
    buf = builder.Output()
    data = buf.decode('latin-1')
    r = requests.post('http://localhost:5000/predict', data={'packet': data})
    print r.text

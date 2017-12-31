from iface_manager import start_mon_iface, stop_mon_iface
from scapy.layers.dot11 import Dot11, Dot11Beacon
from scapy.sendrecv import sniff

seen = []


def sniff_beacon(packet):
    if packet.haslayer(Dot11Beacon):
        info = packet[Dot11].info.decode()
        if info not in seen:
            seen.append(info)
            print(info)


if __name__ == '__main__':
    start_mon_iface()
    sniff(iface='mon0', prn=sniff_beacon)
    stop_mon_iface()

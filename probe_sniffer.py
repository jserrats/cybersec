from iface_manager import start_mon_iface, stop_mon_iface
import csv
from binascii import hexlify
from datetime import datetime
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt, RadioTap
from scapy.sendrecv import sniff


class ProbePacket:
    def __init__(self, packet):
        self.time = (datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()
        self.SA = packet[Dot11].addr2
        self.SeqN = str(int(packet[Dot11].SC) // 16)
        self.dbm = str(packet[RadioTap].dbm_antsignal)
        self.OUID = []
        self.SSID = ''
        self.vendor_data = ''
        self.HTCapabilities = ''
        self.HT_A_MPDU = ''
        self.Suported_rates = ''
        self.Extended_Suported_rates = ''
        self.Extended_capabilities = ''

        try:
            self.organization = oui[self.SA[0:8]]
        except KeyError:
            self.organization = "RANDOM"

        if packet.haslayer(Dot11Elt):
            dot11elt = packet.getlayer(Dot11Elt)

            while dot11elt:
                # SSID 0
                if dot11elt.ID == 0:
                    if dot11elt.info:
                        try:
                            self.SSID = dot11elt.info.decode()
                        except UnicodeDecodeError:
                            self.SSID = dot11elt.info

                # vendor specific OUI 221
                if dot11elt.ID == 221:
                    self.OUID.append(hexlify(dot11elt.info[0:3]).decode())  # el OUID son els 4 primers bytes
                    pre_vendor_data = ''.join(chr(i) for i in dot11elt.info if (i < 123) and (i > 64))
                    if len(pre_vendor_data) < 3:
                        self.vendor_data = ''
                    else:
                        self.vendor_data = pre_vendor_data

                # iterate
                dot11elt = dot11elt.payload.getlayer(Dot11Elt)

    def __str__(self):
        msg = '| {:10.2f} | SA: {} | ORG: {:^40} | dBm: {} '.format(self.time, self.SA,
                                                                    self.organization, self.dbm)

        if self.SSID:
            msg += '| SSID: {} '.format(self.SSID)

        if self.OUID:
            ouid_str = ''
            for ouid in self.OUID:
                try:
                    ouid_str += oui['{}:{}:{}'.format(ouid[0:2], ouid[2:4], ouid[4:6])][:-1] + "|"
                except KeyError:
                    ouid_str += ouid + "|"

            msg += '| OUI: [{}] '.format(ouid_str[:-2])

        if self.vendor_data:
            msg += '| Vendor data: {} '.format(self.vendor_data)

        return msg


class Sniffer:
    def __init__(self, iface, iface_mac=''):
        self.filter = iface_mac
        self.iface = iface
        try:
            sniff(count=0, store=0, iface=self.iface, prn=self.sniff_probe)
        except KeyboardInterrupt:
            pass

    def sniff_probe(self, packet):
        if packet.haslayer(Dot11ProbeReq) and packet[Dot11].addr2 != self.filter:
            print(ProbePacket(packet))


def get_dict_from_csv():
    with open('oui.csv') as f:
        return dict(filter(None, csv.reader(f)))


oui = get_dict_from_csv()

if __name__ == '__main__':
    mon, interface_mac = start_mon_iface()
    Sniffer(mon, interface_mac)
    stop_mon_iface()

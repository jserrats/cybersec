from iface_manager import start_mon_iface, stop_mon_iface
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap, Dot11Beacon
from scapy.sendrecv import sniff
from os import system
from misc import oui_dict
import time

import threading

seen = []


class BeaconPacket:
    def __init__(self, packet):
        self.SA = packet[Dot11].addr2
        self.dbm = str(packet[RadioTap].dbm_antsignal)
        self.SSID = ''
        self.channel = -1

        try:
            self.organization = oui_dict[self.SA[0:8]]
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
                if dot11elt.ID == 3:
                    self.channel = int.from_bytes(dot11elt.info, byteorder='big', signed=False)

                # iterate
                dot11elt = dot11elt.payload.getlayer(Dot11Elt)

    def __str__(self):
        txt = '| SA: {} | dBm: {} | Channel: {:>2} | SSID: {:^20} | ORG: {:^40} |'.format(self.SA, self.dbm,
                                                                                          self.channel,
                                                                                          self.SSID,
                                                                                          self.organization)
        return txt


def sniff_beacon(packet):
    if packet.haslayer(Dot11Beacon):
        beacon = BeaconPacket(packet)
        if beacon.SA not in seen:
            print(beacon)
            seen.append(beacon.SA)


class ChannelSwitcher(threading.Thread):
    def __init__(self, mon):
        self.mon = mon
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.flag = True

    def run(self):
        while self.flag:
            for i in range(1, 15):
                self.change_channel(i)
                time.sleep(0.1)

    def stop(self):
        self.flag = False

    def change_channel(self, channel_c):
        system('iwconfig ' + self.mon + ' channel ' + str(channel_c))


def main():
    mon, mon_mac = start_mon_iface()
    switcher = ChannelSwitcher(mon)
    try:
        switcher.start()
        sniff(iface=mon, prn=sniff_beacon)
    except KeyboardInterrupt:
        pass
    finally:
        stop_mon_iface()


if __name__ == '__main__':
    main()

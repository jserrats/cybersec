import netifaces
from os import system


def start_mon_iface():
    actual_mon = get_mon_iface()

    if actual_mon is False:
        iface, mon_mac, initial_interfaces = choose_iface()
        system('sudo airmon-ng start ' + iface)
        final_interfaces = netifaces.interfaces()
        new_interface = list(set(final_interfaces) - set(initial_interfaces))[0]
        return new_interface, mon_mac
    else:
        return actual_mon, netifaces.ifaddresses(actual_mon)[netifaces.AF_LINK][0]['addr']


def stop_mon_iface():
    system('sudo airmon-ng stop ' + get_mon_iface())


def get_mon_iface():
    for iface in netifaces.interfaces():
        if "mon" in iface:
            return iface
    return False


def choose_iface():
    initial_interfaces = netifaces.interfaces()

    for count, interface in enumerate(initial_interfaces):
        print(str(count) + ' - ' + interface)

    interface_number = input("Enter interface number: ")

    while not interface_number.isdigit():
        interface_number = input("Enter valid interface number: ")

    while int(interface_number) > len(initial_interfaces):
        interface_number = input("Enter valid interface number: ")

    interface = initial_interfaces[int(interface_number)]

    # return choosen interface name, choosen interface mac, list of all initially available interfaces
    return interface, netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'], initial_interfaces


if __name__ == '__main__':

    actual_mon = get_mon_iface()

    if actual_mon is False:
        print('Choose interface to monitor')
        interface, interface_mac, null = choose_iface()
        system('sudo airmon-ng start ' + interface)

    else:
        system('sudo airmon-ng stop ' + actual_mon)

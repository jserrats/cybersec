import csv
from geolite2 import geolite2


def locate_ip(ip):
    info = geolite2.reader().get(ip)
    location = ' - '
    try:
        location = info['country']['names']['en']
        location = location + ', ' + info['subdivisions'][0]['names']['en']
        location = location + ', ' + info['city']['names']['en']
    except TypeError:
        location = 'Private IP'
    except KeyError:
        pass
    finally:
        return location


def get_dict_from_csv():
    with open('oui.csv') as f:
        return dict(filter(None, csv.reader(f)))


oui_dict = get_dict_from_csv()

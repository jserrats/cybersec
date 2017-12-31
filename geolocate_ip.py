#!/usr/bin/env python3
from geolite2 import geolite2
from sys import argv, stdin


def locate_ip(ip):
    info = geolite2.reader().get(ip)
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


def main():
    if len(argv) == 2:
        ip = locate_ip(argv[1])
    else:
        ip = stdin.readline().replace("\n", "")

    try:
        print(locate_ip(ip))
    except ValueError:
        print("Not a valid IP")


if __name__ == "__main__":
    main()

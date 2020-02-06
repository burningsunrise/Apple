#!/usr/bin/python3
import pyshark
import os, sys, re, uuid


def main():
    last = []
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo"] + sys.argv)
    # this is where you would put the interface="eth0" for example
    capture = pyshark.LiveCapture(interface=interfaces())
    for packet in capture.sniff_continuously(packet_count=5):
        if packet[0].src != ':'.join(re.findall('..', '%012x' % uuid.getnode())):
            if packet[0].src not in last:
                last.append(packet[0].src)
                print(packet[0].src)


def interfaces():
    interfaces = os.listdir("/sys/class/net/")
    interfaces = [x for x in interfaces if "lo" not in x and "wlp" not in x and "tun" not in x]
    if len(interfaces) == 1:
        return interfaces
    else:
        print("Input interface yourself, I couldn't find it!")
        sys.exit()


if __name__ == "__main__":
    main()
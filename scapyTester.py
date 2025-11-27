from scapy.all import *
import signal
import sys
from datetime import datetime

file = open("/home/kali/Desktop/MemoryDB/log.txt", 'w')

def frame_processing(frame):

    file.write(frame[Dot11].addr2.upper() + " " + str(frame[Dot11].SC >> 4) + " " + datetime.now().strftime("%H:%M:%S") + "\n")

def signal_term_handler(signal, frame):
    file.close()
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_term_handler)

sniff(
    timeout=600,
    filter="(wlan type data) || (wlan type mgt subtype probe-req)",
    prn=frame_processing,
    iface="wlan1",
    store=0,
    monitor=True)
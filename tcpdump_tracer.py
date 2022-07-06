#!/usr/bin/python3
import pyshark
from pyshark.packet.packet import Packet
from pyshark.capture.pipe_capture import PipeCapture

import sys
import time
from datetime import datetime, timedelta, timezone
import getopt
import socket
import subprocess
from ipaddress import ip_address, ip_network


def usage() -> None:
    print("influxdb-networkmonitor: monitor traffic on your network and store in influxdb")
    print("https://github.com/robfox92/influxdb-networkmonitor")
    print("")
    print("  -h, --help             print this text and exit")
    print("router otions:")
    print("  --router_address       address of router to collect traffic data from (default:10.0.0.1)")
    print("  --router_port          port the router accepts ssh connections on (default:22)")
    print("  --traffic_subnet       subnet to collect traffic data from (default: 10.0.0.0/8)")
    print("  --ssh_options          options for the ssh session")

def get_local_ip(router_address:str, router_port:int) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((router_address, router_port))
        return s.getsockname()[0]

try:
    opts, args = getopt.getopt(sys.argv[1:], ["h"], \
                               ["help", "router_address=", "router_port=", "traffic_subnet=", "ssh_options="])
except getopt.GetoptError as e:
    print(e)
    usage()
    exit(1)


def main() -> None:
    router_address = "10.0.0.1"
    router_port = 22
    traffic_subnet = "10.0.0.0/8"
    ssh_options = ""
    
    for o,a in opts:
        if o in ["--help", "-h"]:
            usage()
            exit()
        if o in ["--router_address"]:
            router_address = a
            continue
        if o in ["--router_port"]:
            try:
                router_port = int(a)
                continue
            except:
                print("error: failed to parse router_port")
                usage()
                exit(1)
        if o in ["--traffic_subnet"]:
            traffic_subnet = a
            continue
        if o in ["--ssh_options"]:
            ssh_options = a
    
    
    local_ip = get_local_ip(router_address=router_address, router_port=router_port)
    ip_range = ip_network(traffic_subnet)

    ssh_command = f"/usr/sbin/tcpdump ip and not port {router_port} and net {traffic_subnet} and host not {router_address} -U -w - "
    ssh_args = ["ssh", ssh_options, router_address, ssh_command]

    try:
        wireshark_source = subprocess.Popen(ssh_args, stdout=subprocess.PIPE)
        packet: Packet
        for packet in PipeCapture(wireshark_source.stdout):
            packet_length = int(packet.length)
            packet_time = packet.sniff_time.isoformat()
            src_ip = ip_address(packet['ip'].src)
            dst_ip = ip_address(packet['ip'].dst)
            # ignore broadcasts
            if src_ip.packed[3] == 255: continue
            if dst_ip.packed[3] == 255: continue
            if src_ip in ip_range:
                print(f"{packet_time} SRC {packet['ip'].src} {packet['eth'].src} {packet_length}")
            if dst_ip in ip_range:
                print(f"{packet_time} DST {packet['ip'].dst} {packet['eth'].dst} {packet_length}")

    except Exception as e:
        print(e)

    finally:
        wireshark_source.kill()


if __name__ == "__main__":
    main()
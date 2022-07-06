#!/usr/bin/python3
import pyshark
from pyshark.packet.packet import Packet
from pyshark.capture.pipe_capture import PipeCapture

import sys
import time
import asyncio
from asyncio import Task
from datetime import datetime, timedelta
import getopt
from influxdb_client import InfluxDBClient, WriteApi
from influxdb_client.client.write_api import ASYNCHRONOUS, SYNCHRONOUS
from influxdb_client.client.write.point import WritePrecision
import socket
import subprocess
from ipaddress import ip_address, ip_network
import random

def usage() -> None:
    print("influxdb-networkmonitor: monitor traffic on your network and store in influxdb")
    print("https://github.com/robfox92/influxdb-networkmonitor")
    print("")
    print("  -h, --help             print this text and exit")
    print("router otions:")
    print("  --router_address       address of router to collect traffic data from (default:10.0.0.1)")
    print("  --router_port          port the router accepts ssh connections on (default:22)")
    print("  --traffic_subnet       subnet to collect traffic data from (default: 10.0.0.0/8)")


def get_local_ip(router_address:str, router_port:int) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((router_address, router_port))
        return s.getsockname()[0]

try:
    opts, args = getopt.getopt(sys.argv[1:], ["h"], \
                               ["help", "router_address=", "router_port=", "traffic_subnet="])
except getopt.GetoptError as e:
    print(e)
    usage()
    exit(1)

async def send_stats(   influxdb_writer: WriteApi, influxdb_bucket: str, influxdb_org: str, \
                        timestamp: datetime, send_interval_seconds: float, \
                        ip_to_bytes_sent: dict, ip_to_bytes_recv: dict, \
                        ip_to_eth: dict, ip_to_host: dict) -> None:
    writes= []
    write_timestamp=timestamp.timestamp()
    for ip, count in ip_to_bytes_sent.items():
        writes.append(f"net,eth={ip_to_eth[ip]},host={ip},name={ip_to_host[ip]} bytes_sent_per_sec={count/send_interval_seconds} {write_timestamp}")
    for ip, count in ip_to_bytes_recv.items():
        writes.append(f"net,eth={ip_to_eth[ip]},host={ip},name={ip_to_host[ip]} bytes_recv_per_sec={count/send_interval_seconds}  {write_timestamp}")
    influxdb_writer.write(influxdb_bucket, influxdb_org, writes,write_precision=WritePrecision.S)

def main() -> None:

    router_address = "10.0.0.1"
    router_port = 22
    traffic_subnet = "10.0.0.0/8"
    
    
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
    
    local_ip = get_local_ip(router_address=router_address, router_port=router_port)
    ip_range = ip_network(traffic_subnet)


    ssh_command = f"/usr/sbin/tcpdump ip and not port {router_port} and net {traffic_subnet} and host not {router_address} and host not {local_ip} -U -w - "
    try:
        wireshark_source = subprocess.Popen(["ssh", router_address, ssh_command], \
                                            stdout=subprocess.PIPE)
        
        packet: Packet
        for packet in PipeCapture(wireshark_source.stdout):


            packet_length = int(packet.length)
            src_ip = ip_address(packet['ip'].src)
            dst_ip = ip_address(packet['ip'].dst)

            # ignore broadcasts
            if src_ip.packed[3] == 255: continue
            if dst_ip.packed[3] == 255: continue

            if src_ip in ip_range:
                print(f"SRC {packet['ip'].src} {packet_length}")

                
            if dst_ip in ip_range:
                print(f"DST {packet['ip'].dst} {packet_length}")

            
            

    except Exception as e:
        print(e)


    finally:
        wireshark_source.kill()


if __name__ == "__main__":
    main()
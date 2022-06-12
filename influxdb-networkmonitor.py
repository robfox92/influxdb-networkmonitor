#!/usr/bin/python3
import pyshark
from pyshark.packet.packet import Packet
from pyshark.capture.pipe_capture import PipeCapture

import sys
from datetime import datetime, timedelta
import getopt
from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import ASYNCHRONOUS, SYNCHRONOUS
import socket
import subprocess
from ipaddress import ip_address, ip_network

def usage() -> None:
    print("  -h, --help             print this text and exit")
    print("influxdb options:")
    print("  --influxdb_url         address of influxdb instance (default: http://localhost:8086)")
    print("  --influxdb_token       token for accessing influxdb")
    print("  --influxdb_org         influxdb organisation to write to")
    print("  --influxdb_bucket      influxdb bucket to write to")
    print("router otions:")
    print("  --router_address       address of router to collect traffic data from (default:10.0.0.1)")
    print("  --router_port          port the router accepts ssh connections on (default:22)")
    print("  --traffic_subnet       subnet to collect traffic data from (default: 10.0.0.0/8)")


def get_local_ip(router_address:str, router_port:int) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((router_address, router_port))
        return s.getsockname()[0]

try:
    opts, args = getopt.getopt(sys.argv[1:], ["h"], ["help", \
                                                    "influxdb_url=", "influxdb_token=", "influxdb_org=", "influxdb_bucket=", \
                                                     "router_address=", "router_port=", "traffic_subnet="])
except getopt.GetoptError:
    usage()
    exit(1)

def main() -> None:
    influxdb_url = 'http://localhost:8086'
    influxdb_token = ""
    influxdb_org = ""
    influxdb_bucket = ""
    send_interval_seconds = 5 
    
    send_interval = timedelta(seconds=send_interval_seconds)
    maintenance_interval = timedelta(minutes=10)

    router_address = "10.0.0.1"
    router_port = 22
    traffic_subnet = "10.0.0.0/8"
    
    
    for o,a in opts:
        if o in ["--help", "-h"]:
            usage()
            exit()
        if o in ["--influxdb_url"]:
            influxdb_url = a
            continue
        if o in ["--influxdb_token"]:
            influxdb_token = a
            continue
        if o in ["--influxdb_org"]:
            influxdb_org = a
            continue
        if o in ["--influxdb_bucket"]:
            influxdb_bucket = a
            continue
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

    # TODO: validate that required opts are set correctly
    
    local_ip = get_local_ip(router_address=router_address, router_port=router_port)
    ip_range = ip_network(traffic_subnet)

    # set up our comms with influx
    influx_client = InfluxDBClient(url=influxdb_url, token=influxdb_token, org=influxdb_org)
    influxdb_writer = influx_client.write_api(write_options=ASYNCHRONOUS)
    ssh_command = f"/usr/sbin/tcpdump ip and host not {local_ip} and host not {router_address} -U -w - "
    try:
        wireshark_source = subprocess.Popen(["ssh", router_address, ssh_command], \
                                            stdout=subprocess.PIPE)
        
        last_send_time = datetime.now()
        last_maintenance_time = datetime.now()
        
        ip_to_bytes_sent: dict[str,int] = dict()
        ip_to_bytes_recv: dict[str,int] = dict()
        ip_to_host: dict[str,str] = dict()
        ip_to_eth: dict[str,str] = dict()
        packet: Packet
        for packet in PipeCapture(wireshark_source.stdout):
            current_time = packet.sniff_time
            packet_length = int(packet.length)
            src_ip = ip_address(packet['ip'].src)
            dst_ip = ip_address(packet['ip'].dst)

            # ignore broadcasts
            if src_ip.packed[3] == 255: continue
            if dst_ip.packed[3] == 255: continue

            if src_ip in ip_range:
                if packet['ip'].src not in ip_to_bytes_sent.keys():
                    ip_to_bytes_sent[packet['ip'].src] = 0
                    ip_to_eth[packet['ip'].src] = packet['eth'].src
                    try:
                        ip_to_host[packet['ip'].src] = socket.gethostbyaddr(packet['ip'].src)[0]
                    except:
                        ip_to_host[packet['ip'].src] = "unknown"
                ip_to_bytes_sent[packet['ip'].src] += packet_length
            if dst_ip in ip_range:
                if packet['ip'].dst not in ip_to_bytes_recv.keys():
                    ip_to_bytes_recv[packet['ip'].dst] = 0
                    ip_to_eth[packet['ip'].dst] = packet['eth'].dst
                    try:
                        ip_to_host[packet['ip'].dst] = socket.gethostbyaddr(packet['ip'].dst)[0]
                    except:
                        ip_to_host[packet['ip'].dst] = "unknown"
                ip_to_bytes_recv[packet['ip'].dst] += packet_length

            # periodically send data to influx
            if current_time - last_send_time > send_interval:
                writes = []
                for ip, count in ip_to_bytes_sent.items():
                    writes.append(f"net,host={ip},name={ip_to_host[ip]},eth={ip_to_eth[ip]} bytes_sent_per_sec={count/send_interval_seconds}")
                    ip_to_bytes_sent[ip] = 0
                for ip, count in ip_to_bytes_recv.items():
                    writes.append(f"net,host={ip},name={ip_to_host[ip]},eth={ip_to_eth[ip]} bytes_recv_per_sec={count/send_interval_seconds}")
                    ip_to_bytes_recv[ip] = 0
                influxdb_writer.write(influxdb_bucket, influxdb_org, writes)
                last_send_time = current_time
                
                if current_time - last_maintenance_time > maintenance_interval:
                    # clear our maps every 10 mins or so
                    # this means that if any ip_to_host mappings are altered we'll see them
                    # same with ip_to_eth
                    ip_to_bytes_sent: dict[str,int] = dict()
                    ip_to_bytes_recv: dict[str,int] = dict()
                    ip_to_host: dict[str,str] = dict()
                    ip_to_eth: dict[str,str] = dict()
                    last_maintenance_time = current_time




    finally:
        wireshark_source.kill()


if __name__ == "__main__":
    main()
#!/usr/bin/python3
import pyshark
from pyshark.packet.packet import Packet
from pyshark.capture.pipe_capture import PipeCapture

import sys
import time
from datetime import datetime, timedelta
import getopt
from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import ASYNCHRONOUS, SYNCHRONOUS
from influxdb_client.client.write.point import WritePrecision
import socket
import subprocess
from ipaddress import ip_address, ip_network

def usage() -> None:
    print("influxdb-networkmonitor: monitor traffic on your network and store in influxdb")
    print("https://github.com/robfox92/influxdb-networkmonitor")
    print("")
    print("  -h, --help             print this text and exit")
    print("influxdb options:")
    print("  --influxdb_url         address of influxdb instance (default: http://localhost:8086)")
    print("  --influxdb_token       token for accessing influxdb")
    print("  --influxdb_org         influxdb organisation to write to")
    print("  --influxdb_bucket      influxdb bucket to write to")
    print("  --send_interval        seconds to wait between sending to influxdb (default: 5)")
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
                               ["help", \
                                "influxdb_url=", "influxdb_token=", "influxdb_org=", "influxdb_bucket=", "send_interval=" \
                                "router_address=", "router_port=", "traffic_subnet="])
except getopt.GetoptError:
    usage()
    exit(1)

def main() -> None:
    influxdb_url = 'http://localhost:8086'
    influxdb_token = ""
    influxdb_org = ""
    influxdb_bucket = ""
    
    send_interval = timedelta(seconds=5)
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
        if o in ["--send_interval"]:
            try:
                send_interval.seconds = int(a)
            except:
                print("error: failed to parse send_interval")
                usage()
                exit(1)
            continue

    # TODO: validate influxdb_token, influxdb_org, influxdb_bucket
    
    local_ip = get_local_ip(router_address=router_address, router_port=router_port)
    ip_range = ip_network(traffic_subnet)

    if not (influxdb_url.startswith("http://") or influxdb_url.startswith("https://")):
        influxdb_url = "http://" + influxdb_url

    # set up our comms with influx
    influx_client = InfluxDBClient(url=influxdb_url, token=influxdb_token, org=influxdb_org)
    if influx_client.health().status != "pass":
        print(f"error: failed to connect to influxdb at {influxdb_url}")
        exit(1)
    
    influxdb_writer = influx_client.write_api(write_options=ASYNCHRONOUS)


    ssh_command = f"/usr/sbin/tcpdump ip and not port {router_port} and net {traffic_subnet} and host not {router_address} -U -w - "
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
            delay = datetime.now() - current_time
            if delay > timedelta(seconds=5):
                print("warning: packet processing is not keeping up")
                print(f"delay: {delay}")

            packet_length = int(packet.length)
            src_ip = ip_address(packet['ip'].src)
            dst_ip = ip_address(packet['ip'].dst)

            # ignore broadcasts
            if src_ip.packed[3] == 255: continue
            if dst_ip.packed[3] == 255: continue

            if src_ip in ip_range:
                try:
                    ip_to_bytes_sent[packet['ip'].src] += packet_length
                except KeyError:
                    ip_to_bytes_sent[packet['ip'].src] = 0
                    ip_to_eth[packet['ip'].src] = packet['eth'].src
                    try:
                        ip_to_host[packet['ip'].src] = socket.gethostbyaddr(packet['ip'].src)[0]
                    except:
                        ip_to_host[packet['ip'].src] = "unknown"
                    ip_to_bytes_sent[packet['ip'].src] += packet_length
                
            if dst_ip in ip_range:
                try:
                    ip_to_bytes_recv[packet['ip'].dst] += packet_length
                except KeyError:
                    ip_to_bytes_recv[packet['ip'].dst] = 0
                    ip_to_eth[packet['ip'].dst] = packet['eth'].dst
                    try:
                        ip_to_host[packet['ip'].dst] = socket.gethostbyaddr(packet['ip'].dst)[0]
                    except:
                        ip_to_host[packet['ip'].dst] = "unknown"
                    ip_to_bytes_recv[packet['ip'].dst] += packet_length

            # periodically send data to influx
            if current_time - last_send_time > send_interval:
                timestamp = int(current_time.timestamp())
                writes = []
                for ip, count in ip_to_bytes_sent.items():
                    writes.append(f"net,eth={ip_to_eth[ip]},host={ip},name={ip_to_host[ip]} bytes_sent_per_sec={count/send_interval.total_seconds()} {timestamp}")
                    ip_to_bytes_sent[ip] = 0
                for ip, count in ip_to_bytes_recv.items():
                    writes.append(f"net,eth={ip_to_eth[ip]},host={ip},name={ip_to_host[ip]} bytes_recv_per_sec={count/send_interval.total_seconds()}  {timestamp}")
                    ip_to_bytes_recv[ip] = 0
                influxdb_writer.write(influxdb_bucket, influxdb_org, writes,write_precision=WritePrecision.S)
                last_send_time = current_time
                
                if current_time - last_maintenance_time > maintenance_interval:
                    # clear our maps every 10 mins or so
                    # this means that if any ip_to_host or ip_to_eth mappings are altered we'll see them
                    # we clear out all of our maps because we add to ip_to_host when we add to ip_to_bytes_{sent,recv}
                    ip_to_bytes_sent: dict[str,int] = dict()
                    ip_to_bytes_recv: dict[str,int] = dict()
                    ip_to_host: dict[str,str] = dict()
                    ip_to_eth: dict[str,str] = dict()
                    last_maintenance_time = current_time

    except Exception as e:
        pass


    finally:
        wireshark_source.kill()


if __name__ == "__main__":
    main()
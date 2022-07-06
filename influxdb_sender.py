#!/usr/bin/python3

from datetime import datetime, timedelta
import getopt
import random
import socket
import subprocess
import sys
import threading
from typing import Union

from influxdb_client import InfluxDBClient, WriteApi
from influxdb_client.client.write_api import ASYNCHRONOUS, SYNCHRONOUS
from influxdb_client.client.write.point import WritePrecision





def usage() -> None:
    print("https://github.com/robfox92/influxdb-networkmonitor")
    print("")
    print("  -h, --help                 print this text and exit")
    print("  --debug_level              how loud do you want this to be? (default: 0, loudest: -1)")
    print("  --maintenance_interval     minutes between cleaning up local caches. integers only. (default: 5)")
    print("influxdb options:")  
    print("  --influxdb_url             address of influxdb instance (default: http://localhost:8086)")
    print("  --influxdb_token           token for accessing influxdb")
    print("  --influxdb_org             influxdb organisation to write to")
    print("  --influxdb_bucket          influxdb bucket to write to")
    print("  --send_interval            seconds to wait between sending to influxdb. integers only. (default: 5)")
    print("router otions:") 
    print("  --router_address           address of router to collect traffic data from (default:10.0.0.1)")
    print("  --router_port              port the router accepts ssh connections on (default:22)")
    print("  --ssh_options              options for the ssh session")

try:
    opts, args = getopt.getopt(sys.argv[1:], ["h"], \
                               ["help", "debug_level=", "maintenance_interval=",\
                                "influxdb_url=", "influxdb_token=", "influxdb_org=", "influxdb_bucket=", "send_interval=", \
                                "router_address=", "router_port=", "traffic_subnet=", "ssh_options="])
except getopt.GetoptError as e:
    print(e)
    usage()
    exit(1)


global DEBUG_LEVEL
DEBUG_LEVEL = 0


def write_log_message(timestamp:datetime, message_debug_level:int, method_name:str, messages:Union[str,list[str]]):
    global DEBUG_LEVEL
    if DEBUG_LEVEL >= message_debug_level:
        timestamp_padding = len(str(timestamp))
        if type(messages) != list: messages = [messages]
        ostr=f"{timestamp} DEBUG_LEVEL={message_debug_level} {method_name}"
        for m in messages:
            ostr += f"\n{' '*(timestamp_padding//4)}{m}"
        print(ostr)


def send_stats(   influxdb_writer: WriteApi, influxdb_bucket: str, influxdb_org: str, \
                        timestamp: datetime, send_interval_seconds: float, \
                        ip_to_bytes_sent: dict, ip_to_bytes_recv: dict, \
                        ip_to_eth: dict, ip_to_host: dict) -> None:
    writes= []
    write_timestamp=int(timestamp.timestamp())
    for ip, count in ip_to_bytes_sent.items():
        writes.append(f"net,eth={ip_to_eth[ip]},host={ip},name={ip_to_host[ip]} bytes_sent_per_sec={count/send_interval_seconds} {write_timestamp}")
    for ip, count in ip_to_bytes_recv.items():
        writes.append(f"net,eth={ip_to_eth[ip]},host={ip},name={ip_to_host[ip]} bytes_recv_per_sec={count/send_interval_seconds}  {write_timestamp}")
    
    write_log_message(timestamp, 5, "send_stats()", ["sending events to influxdb", f"{len(writes)} lines to write"])
    
    influxdb_writer.write(influxdb_bucket, influxdb_org, writes,write_precision=WritePrecision.S)
    

def main() -> None:
    
    influxdb_url = 'http://localhost:8086'
    influxdb_token = ""
    influxdb_org = ""
    influxdb_bucket = ""
    global DEBUG_LEVEL
    send_interval = timedelta(seconds=5)
    maintenance_interval = timedelta(minutes=5)
    ssh_options = ""

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
        if o in ["--debug_level"]:
            try:
                DEBUG_LEVEL = int(a)
            except:
                print("error: failed to parse debug_level")
                usage()
                exit(1)
            continue
        if o in ["--maintenance_interval"]:
            try:
                maintenance_interval = timedelta(minutes=int(a))
            except:
                print("error: failed to parse maintenance interval")
                usage()
                exit(1)
        if o in ["--ssh_options"]:
            ssh_options = a
    
    
    if DEBUG_LEVEL < 0: DEBUG_LEVEL = 99999999

    # TODO: validate influxdb_token, influxdb_org, influxdb_bucket
    

    if not (influxdb_url.startswith("http://") or influxdb_url.startswith("https://")):
        influxdb_url = "http://" + influxdb_url

    # set up our comms with influx
    influx_client = InfluxDBClient(url=influxdb_url, token=influxdb_token, org=influxdb_org)
    if influx_client.health().status != "pass":
        print(f"error: failed to connect to influxdb at {influxdb_url}")
        exit(1)
    
    influxdb_writer = influx_client.write_api(write_options=ASYNCHRONOUS)
    
    
    trace_source_args = ["python", "./tcpdump_tracer.py"]
    if router_address != "":
        trace_source_args.append("--router_address")
        trace_source_args.append(str(router_address))
    if router_port != "":
        trace_source_args.append("--router_port")
        trace_source_args.append(str(router_port))
    if traffic_subnet != "":
        trace_source_args.append("--traffic_subnet")
        trace_source_args.append(str(traffic_subnet))
    if ssh_options != "":
        trace_source_args.append("--ssh_options")
        trace_source_args.append(str(ssh_options))
    trace_source = subprocess.Popen(trace_source_args, stdout=subprocess.PIPE)
    
    try:
        last_send_time = datetime.now()
        last_maintenance_time = datetime.now()
        
        ip_to_bytes_sent: dict[str,int] = dict()
        ip_to_bytes_recv: dict[str,int] = dict()
        ip_to_host: dict[str,str] = dict()
        ip_to_eth: dict[str,str] = dict()

        send_thread_list: list[threading.Thread] = []

        for line in trace_source.stdout:
            try:
                packet_time_bstr, direction_bstr, ip_bstr, eth_bstr, size_bstr = line.split()
                packet_time = datetime.fromisoformat(packet_time_bstr.decode('utf-8'))
                direction = direction_bstr.decode('utf-8')
                ip = ip_bstr.decode('utf-8')
                size = int(size_bstr.decode('utf-8'))
                eth = eth_bstr.decode('utf-8')
            except ValueError:
                # if we can't unpack the line, it's malformed. just go to the next line
                continue


            if ip not in ip_to_eth.keys(): 
                ip_to_eth[ip] = eth
            
            if ip not in ip_to_host.keys():
                try:
                    ip_to_host[ip] = socket.gethostbyaddr(ip)[0].replace(".local","")
                except:
                    ip_to_host[ip] = "unknown"

            if direction == "SRC":
                if ip not in ip_to_bytes_sent.keys():
                    ip_to_bytes_sent[ip] = 0
                ip_to_bytes_sent[ip] += size
                
            if direction == "DST":
                if ip not in ip_to_bytes_recv.keys():
                    ip_to_bytes_recv[ip] = 0
                ip_to_bytes_recv[ip] += size

            if packet_time - last_send_time > send_interval:
                write_log_message(packet_time, 4, "main()", ["sending data to influxdb", f"bucket = {influxdb_bucket}", f"org    = {influxdb_org}"])
                send_kwargs = {
                    "influxdb_writer":influxdb_writer, "influxdb_bucket":influxdb_bucket, "influxdb_org":influxdb_org, \
                    "timestamp":packet_time, "send_interval_seconds":send_interval.total_seconds(), \
                        "ip_to_bytes_sent":ip_to_bytes_sent, "ip_to_bytes_recv":ip_to_bytes_recv, \
                        "ip_to_host":ip_to_host, "ip_to_eth":ip_to_eth \
                }
                send_thread = threading.Thread(target=send_stats, kwargs=send_kwargs)
                send_thread.start()
                
                send_thread_list.append(send_thread)
                # reset our stats to 0
                ip_to_bytes_sent = {ip:0 for ip in ip_to_bytes_sent.keys()}
                ip_to_bytes_recv = {ip:0 for ip in ip_to_bytes_recv.keys()}

                last_send_time = packet_time
                    

            
            if packet_time - last_maintenance_time > maintenance_interval:
                current_time = datetime.now()
                processing_lag = current_time - packet_time
                write_log_message(packet_time, 3, "main()", 
                    ["performing maintenance", f"real time = {current_time}",f"processing lag: {processing_lag}"]
                )
                # completely clear out our stats so we don't keep sending 0 for inactive hosts
                ip_to_bytes_sent = dict()
                ip_to_bytes_recv = dict()

                # if a ip<->host mapping changes we'll know about it
                ip_to_host = dict()
                # if a ip<->eth mapping changes we'll know about it
                ip_to_eth = dict()

                # clear out all refs to completed send threads
                for t in send_thread_list.copy():
                    if not t.is_alive():
                        send_thread_list.remove(t)

                last_maintenance_time = packet_time
            
    except Exception as e:
        print(e)



if __name__ == "__main__":
    main()
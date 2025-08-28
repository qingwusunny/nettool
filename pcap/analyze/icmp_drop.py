#!/usr/bin/env python3
from scapy.all import *
from datetime import datetime
import sys
import csv
import argparse
from collections import defaultdict
from multiprocessing import Pool
from functools import partial
import os

MAX_DIFF_TIME = 10
PCAP_DIR = "/root/pcap/"
WGET_PATH = "http://192.168.17.20/everoute/dev/zwtop/tcpdump/"
NODE_MAP = {
    "10.255.0.99": "em1-10.255.0.99.pcap",
    "10.255.0.109": "enp134s0f1np1-10.255.0.109.pcap",
    "10.255.0.85": "enp59s0f1np1-10.255.0.85.pcap",
    "10.255.0.100": "ens1f0-10.255.0.100.pcap",
    "10.255.0.103": "ens1f0-10.255.0.103.pcap",
    "10.255.0.104": "ens1f0-10.255.0.104.pcap",
    "10.255.0.21": "ens1f0-10.255.0.21.pcap",
    "10.255.0.105": "ens1f1-10.255.0.105.pcap",
    "10.255.0.141": "ens2f1-10.255.0.141.pcap",
    "10.255.0.143": "ens2f1-10.255.0.143.pcap",
    "10.255.0.107": "p3p2-10.255.0.107.pcap",
}

def gen_pcap_ori_file_name(srcip, dstip, index):
    if NODE_MAP[srcip] is None or NODE_MAP[dstip] is None:
        print(f"param srcip {srcip} or dstip {dstip} is invalid")
        raise Exception("param srcip or dstip is invalid")
    return NODE_MAP[srcip] + index, NODE_MAP[dstip] + index

def gen_pcap_file_name(srcip, dstip, index):
    src_pcap = PCAP_DIR + srcip + "_" + srcip + "_" + dstip + ".pcap" + index
    dst_pcap = PCAP_DIR + dstip + "_" + srcip + "_" + dstip + ".pcap" + index
    print(f"\npcap file: {src_pcap} {dst_pcap}")
    return src_pcap, dst_pcap

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="分析两个pcap文件之间的 icmp 丢包情况"
    )
    parser.add_argument("--srcip", help="icmp 源IP", default=None)
    parser.add_argument("--dstip", help="icmp 目的IP", default=None)
    parser.add_argument("--drop_csv", help="write result to csv")
    return parser.parse_args()

def write_to_csv(filename, data, headers=None):
    """通用CSV写入函数"""
    try:
        with open(filename, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            if headers:
                writer.writerow(headers)
            for row in data:
                writer.writerow(row)
        print(f"\n数据已写入: {filename}", file=sys.stderr)
    except Exception as e:
        print(f"写入CSV文件出错: {e}", file=sys.stderr)


def load_icmp_packets(pcap_file, ip1, ip2):
    """加载icmp数据包并记录时间和内容"""
    packets = []
    i = 0
    try:
        for pkt in PcapReader(pcap_file):
            i += 1
            if ICMP in pkt and IP in pkt:  # 确保同时有IP和ICMP层
                if pkt[ICMP].type not in [0, 8]:
                    continue
                if pkt[IP].src not in [ip1, ip2] or pkt[IP].dst not in [ip1, ip2]:
                    continue
                packets.append(
                    {
                        "srcip": pkt[IP].src,
                        "dstip": pkt[IP].dst,
                        "ipid": pkt[IP].id,
                        "icmp_type": pkt[ICMP].type,
                        "icmp_id": pkt[ICMP].id,
                        "icmp_seq": pkt[ICMP].seq,
                        "time": pkt.time,
                        "index": i,
                    }
                )
        print(f"从 {pcap_file} 加载了 {len(packets)} 个ICMP数据包", file=sys.stderr)
        return packets
    except Exception as e:
        print(f"加载 {pcap_file} 出错: {e}", file=sys.stderr)
        return []

def parallel_load(pcap_files, ip1, ip2):
    """并行加载多个不同文件（真并行）"""
    loader = partial(load_icmp_packets, ip1=ip1, ip2=ip2)
    with Pool(processes=len(pcap_files)) as pool:
        return pool.map(loader, pcap_files)

def remove_matched_icmp_pairs_strict(source_pkts):
    """严格移除匹配的ICMP请求和回复包对，检查300ms时间窗口"""
    # 创建回复包的查找字典 {(id, seq, dstip, srcip): [(time, index), ...]}
    reply_dict = {}
    for idx, pkt in enumerate(source_pkts):
        if pkt['icmp_type'] == 0:  # Echo Reply
            key = (pkt['icmp_id'], pkt['icmp_seq'], pkt['dstip'], pkt['srcip'])
            if key not in reply_dict:
                reply_dict[key] = []
            reply_dict[key].append((pkt['time'], idx))
    
    packets_to_remove = set()
    
    # 查找每个请求包对应的回复包
    for req_idx, req_pkt in enumerate(source_pkts):
        if req_pkt['icmp_type'] == 8:  # Echo Request
            # 构建对应的回复包key
            reply_key = (req_pkt['icmp_id'], req_pkt['icmp_seq'], 
                         req_pkt['srcip'], req_pkt['dstip'])
            
            if reply_key in reply_dict:
                req_time = req_pkt['time']
                
                # 查找在300ms时间窗口内且在10个包范围内的回复包
                for rep_time, rep_idx in reply_dict[reply_key]:
                    time_diff = abs(rep_time - req_time)
                    index_diff = rep_idx - req_idx
                    
                    # 检查时间差（300ms以内）
                    if 0 <= time_diff <= 0.3:
                        packets_to_remove.add(req_idx)
                        packets_to_remove.add(rep_idx)
                        break  # 找到一个匹配的就跳出循环
    
    # 创建过滤后的列表
    filtered_packets = [pkt for idx, pkt in enumerate(source_pkts) 
                       if idx not in packets_to_remove]
    
    print(f"移除了 {len(packets_to_remove)} 个匹配的ICMP请求/回复包", file=sys.stderr)
    print(f"剩余 {len(filtered_packets)} 个数据包", file=sys.stderr)
    
    return filtered_packets

def analyze_icmp_communication(src_ori_pcap, source_filtered, target_packets):
    """
    分析目标端对源端未匹配请求的处理情况
    返回分析结果
    """
    analysis_results = []
    
    # 提取源端未匹配的请求包
    source_requests = [pkt for pkt in source_filtered if pkt['icmp_type'] == 8]
    
    print(f"开始分析 {len(source_requests)} 个源端未匹配的ICMP请求...")
    
    for req_idx, source_req in enumerate(source_requests):
        human_time = datetime.fromtimestamp(float(source_req["time"])).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
        result = {
            'source_pcap': src_ori_pcap, 
            'source_human_time': human_time,
            'source_time': source_req["time"],
            'ipid': source_req["ipid"],
            'srcip': source_req["srcip"],
            'dstip': source_req["dstip"],
            'icmp_id': source_req["icmp_id"],
            'icmp_seq': source_req['icmp_seq'],
            'target_received': False,
            'target_replied': False,
            'target_receive_time': None,
            'target_reply_time': None,
        }
        # 查找目标端是否收到了请求
        for target_idx, target_pkt in enumerate(target_packets):
            if (target_pkt['ipid'] == source_req['ipid'] and
                target_pkt['icmp_type'] == 8 and  # 请求包
                target_pkt['icmp_id'] == source_req['icmp_id'] and
                target_pkt['icmp_seq'] == source_req['icmp_seq'] and
                target_pkt['srcip'] == source_req['srcip'] and
                target_pkt['dstip'] == source_req['dstip']) and abs(target_pkt['time'] - source_req['time']) <= 0.3:
                result['target_received'] = True
                result['target_receive_time'] = target_pkt['time']
                break

        # 如果目标端收到了请求，查找是否发送了回复
        if result['target_received']:
            # 查找对应的回复包
            reply_key = (source_req['icmp_id'], source_req['icmp_seq'],
                        source_req['srcip'], source_req['dstip'])
            
            for target_idx, target_pkt in enumerate(target_packets):
                if (target_pkt['icmp_type'] == 0 and  # 回复包
                    target_pkt['icmp_id'] == reply_key[0] and
                    target_pkt['icmp_seq'] == reply_key[1] and
                    target_pkt['srcip'] == reply_key[3] and  # 回复的源IP是请求的目的IP
                    target_pkt['dstip'] == reply_key[2]):   # 回复的目的IP是请求的源IP
                    
                    # 检查回复时间是否在合理范围内（比如2秒内）
                    if (result['target_receive_time'] is not None and
                        abs(target_pkt['time'] - result['target_receive_time']) <= 0.3):
                        result['target_replied'] = True
                        result['target_reply_time'] = target_pkt['time']
                        break
        
        analysis_results.append(list(result.values()))
        
        # 打印进度
        if (req_idx + 1) % 100 == 0:
            print(f"已分析 {req_idx + 1}/{len(source_requests)} 个请求", file=sys.stderr)
    
    return analysis_results

def analyze_pcap_diff(ori_file_name, srcip, dstip,
    source_pcap, target_pcap, drop_csv_file=None
):
    """分析两个pcap文件之间的icmp丢包情况"""
    # 加载数据包
    source_packets, target_packets = parallel_load([source_pcap, target_pcap], srcip, dstip)

    if not source_packets or not target_packets:
        print("错误: 一个或两个pcap文件没有icmp数据包", file=sys.stderr)
        return

    source_packets = remove_matched_icmp_pairs_strict(source_packets)
    print(f"丢包数 {len(source_packets)}")
    if len(source_packets) == 0:
        print(f"pcap 文件 {source_pcap} 没有发生 icmp 丢包")
        return
    result = analyze_icmp_communication(ori_file_name, source_packets, target_packets)
    #print(f"分析结果 {r}")

    # 写入CSV文件
    if drop_csv_file is not None and drop_csv_file != "":
        write_to_csv(
            drop_csv_file,
            result,
            None,
        )

def prepare_pcap(srcip, dstip, index):
    src_ori_pcap, dst_ori_pcap = gen_pcap_ori_file_name(srcip, dstip, index)
    src_pcap, dst_pcap = gen_pcap_file_name(srcip, dstip, index)
    src_ori_wget_cmd = "wget -P " + PCAP_DIR + " " + WGET_PATH + src_ori_pcap
    res = os.system(src_ori_wget_cmd)
    if res != 0:
        print(f"cmd {src_ori_wget_cmd} failed, errcode: {res}")
        raise Exception("exec cmd failed")
    dst_ori_wget_cmd = "wget -P " + PCAP_DIR + " " + WGET_PATH + dst_ori_pcap
    res = os.system(dst_ori_wget_cmd)
    if res != 0:
        print(f"cmd {dst_ori_wget_cmd} failed, errcode: {res}")
        raise Exception("exec cmd failed")
    src_tshark_cmd = 'tshark -r %s -Y "(ip.src eq %s and ip.dst eq %s and icmp.type eq 8) or (ip.src eq %s and ip.dst eq %s and icmp.type eq 0)" -w %s' % (PCAP_DIR + src_ori_pcap, srcip, dstip, dstip, srcip, src_pcap)
    res = os.system(src_tshark_cmd)
    if res != 0:
        print(f"cmd {src_tshark_cmd} failed, errcode: {res}")
        raise Exception("exec cmd failed")
    dst_tshark_cmd = 'tshark -r %s -Y "(ip.src eq %s and ip.dst eq %s and icmp.type eq 8) or (ip.src eq %s and ip.dst eq %s and icmp.type eq 0)" -w %s' % (PCAP_DIR + dst_ori_pcap, srcip, dstip, dstip, srcip, dst_pcap)
    res = os.system(dst_tshark_cmd)
    if res != 0:
        print(f"cmd {dst_tshark_cmd} failed, errcode: {res}")
        raise Exception("exec cmd failed")
    return src_ori_pcap, src_pcap, dst_pcap

def clean_pcap():
    rm_cmd = "rm -f " + PCAP_DIR + "*.pcap*"
    res = os.system(rm_cmd)
    if res != 0:
        print(f"cmd {rm_cmd} failed, errcode: {res}")
        raise Exception("exec cmd failed")

def process(srcip, dstip, drop_csv):
    for i in range(0, 10):
        index = "%d"%i
        src_ori_pcap, src_pcap, dst_pcap = prepare_pcap(srcip, dstip, index)
        analyze_pcap_diff(
            ori_file_name=src_ori_pcap,
            srcip=srcip,
            dstip=dstip,
            source_pcap=src_pcap,
            target_pcap=dst_pcap,
            drop_csv_file=drop_csv,
        )
        clean_pcap()

if __name__ == "__main__":
    args = parse_args()
    write_to_csv(args.drop_csv, [], [
                "source_pcap",
                "source_human_time",
                "source_time",
                "ipid",
                "srcip",
                "dstip"
                "icmp_id",
                "icmp_seq",
                "target_received",
                'target_replied',
                'target_receive_time',
                'target_reply_time'
            ])
    if args.srcip is not None and args.dstip is not None:
        process(args.srcip, args.dstip, args.drop_csv)
    else:
        ips1 = ["10.255.0.107", "10.255.0.143", "10.255.0.141", "10.255.0.105"]
        ips = list(NODE_MAP.keys())
        for srcip in ips1:
            for dstip in ips:
                if srcip == dstip:
                    continue
                process(srcip, dstip, args.drop_csv)

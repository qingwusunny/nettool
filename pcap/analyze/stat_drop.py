#!/usr/bin/env python3
import sys
import csv
import argparse
from collections import defaultdict

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

def stat_from_csv(file):
    stats_request_drop = defaultdict(int)
    stats_reply_drop = defaultdict(int)
    stats_drop_in_host = defaultdict(int)
    stats_drop = defaultdict(int)
    with open(file, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # 跳过第一行
        for row in csv_reader:
            data = [row[4], row[5], row[8], row[9]]
            k = data[0] + "-" + data[1]
            stats_drop[k] += 1
            if data[2] != data[3]:  
                stats_drop_in_host[k] += 1
                continue
            if data[2] == 'False':
                stats_request_drop[k] += 1
                continue
            if data[2] == 'True':
                stats_reply_drop[k] += 1

    header = ["节点", "总丢包数", "request丢包（物理网络）", "reply丢包（物理网络）", "非物理网络丢包"]
    d= []
    for k in stats_drop.keys():
        d.append([k, stats_drop[k], stats_request_drop[k], stats_reply_drop[k], stats_drop_in_host[k]])
    write_to_csv("17.99_stats.csv", d, header)


if __name__ == "__main__": 
    parser = argparse.ArgumentParser(
        description="分析两个pcap文件之间的 icmp 丢包情况"
    )
    parser.add_argument("--csv", help="write result to csv")
    args = parser.parse_args()
    stat_from_csv(args.csv)
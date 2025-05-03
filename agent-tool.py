# !/usr/bin/env python3
import subprocess
import sys
import os
import re
import json
import argparse
import logging
import time
import signal
import datetime
import base64


class TCPDumpMonitor:
    def __init__(self, ports, interface=None, source_ip=None, source_ports=None):
        """初始化監聽器"""
        self.ports = [int(port) for port in ports.split(',')] if isinstance(ports, str) else [ports]
        self.setup_logging()

        self.interface = interface if interface != "any" else None
        self.source_ip = source_ip

        # 處理源端口
        if source_ports:
            if isinstance(source_ports, str) and ',' in source_ports:
                self.source_ports = [int(p) for p in source_ports.split(',')]
            else:
                self.source_ports = [int(source_ports)]
        else:
            self.source_ports = []

        # 建立數據目錄
        self.json_dir = "json_packets"
        self.pcap_dir = "captures"
        os.makedirs(self.json_dir, exist_ok=True)
        os.makedirs(self.pcap_dir, exist_ok=True)

        # 顯示配置信息
        self.logger.info(f"Monitoring ports: {self.ports}")
        if self.source_ip:
            self.logger.info(f"Filtering by source IP: {self.source_ip}")
        if self.source_ports:
            self.logger.info(f"Filtering by source ports: {self.source_ports}")
        self.logger.info(f"JSON packets will be saved in: {os.path.abspath(self.json_dir)}")
        self.logger.info(f"PCAP files will be saved in: {os.path.abspath(self.pcap_dir)}")

        # 處理進程
        self.tcpdump_process = None

    def setup_logging(self):
        """設置日誌記錄"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('packet_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def parse_tcpdump_line(self, line):
        """解析tcpdump輸出行"""
        try:
            # 移除ANSI顏色代碼
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            line = ansi_escape.sub('', line)

            # 基本信息 - 系統當前時間
            capture_time = datetime.datetime.now()

            # 基本信息
            packet_info = {
                "capture_timestamp": capture_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                "raw_output": line.strip(),
                "source_ip": "unknown",
                "source_port": 0,
                "dest_ip": "unknown",
                "dest_port": 0
            }

            # 嘗試提取完整時間戳 (當tcpdump啟用了 -tttt 參數時)
            timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)')
            timestamp_match = timestamp_pattern.search(line)
            if timestamp_match:
                packet_info["packet_timestamp"] = timestamp_match.group(1)

            # 處理IPv4封包
            ipv4_pattern = re.compile(r'IP (\S+) > (\S+):')
            ipv4_match = ipv4_pattern.search(line)
            if ipv4_match:
                src, dst = ipv4_match.groups()

                # 分離IP和端口
                src_parts = src.rsplit(".", 1)
                if len(src_parts) == 2:  # 有端口
                    src_ip = src_parts[0]
                    src_port = src_parts[1]
                    packet_info["source_ip"] = src_ip
                    try:
                        packet_info["source_port"] = int(src_port)
                    except:
                        packet_info["source_port"] = src_port
                else:
                    packet_info["source_ip"] = src

                dst_parts = dst.rsplit(".", 1)
                if len(dst_parts) == 2:  # 有端口
                    dst_ip = dst_parts[0]
                    dst_port = dst_parts[1]
                    packet_info["dest_ip"] = dst_ip
                    try:
                        packet_info["dest_port"] = int(dst_port)
                    except:
                        packet_info["dest_port"] = dst_port
                else:
                    packet_info["dest_ip"] = dst

            # 處理IPv6封包
            ipv6_pattern = re.compile(r'IP6[^:]*: [^:]*: .*? (\S+) > (\S+):')
            if not ipv4_match:  # 如果不是IPv4，嘗試匹配IPv6
                ipv6_match = ipv6_pattern.search(line)
                if ipv6_match:
                    src, dst = ipv6_match.groups()

                    # 分離IPv6地址和端口
                    src_match = re.search(r'([0-9a-fA-F:]+)\.(\d+)', src)
                    if src_match:
                        src_ip, src_port = src_match.groups()
                        packet_info["source_ip"] = src_ip
                        try:
                            packet_info["source_port"] = int(src_port)
                        except:
                            packet_info["source_port"] = src_port
                    else:
                        packet_info["source_ip"] = src

                    dst_match = re.search(r'([0-9a-fA-F:]+)\.(\d+)', dst)
                    if dst_match:
                        dst_ip, dst_port = dst_match.groups()
                        packet_info["dest_ip"] = dst_ip
                        try:
                            packet_info["dest_port"] = int(dst_port)
                        except:
                            packet_info["dest_port"] = dst_port
                    else:
                        packet_info["dest_ip"] = dst

            # 還有另一種IPv6格式
            if packet_info["source_ip"] == "unknown":
                ipv6_alt_pattern = re.compile(r'IP6[^>]* (\S+)\.(\d+) > (\S+)\.(\d+):')
                ipv6_alt_match = ipv6_alt_pattern.search(line)
                if ipv6_alt_match:
                    src_ip, src_port, dst_ip, dst_port = ipv6_alt_match.groups()
                    packet_info["source_ip"] = src_ip
                    packet_info["dest_ip"] = dst_ip
                    try:
                        packet_info["source_port"] = int(src_port)
                        packet_info["dest_port"] = int(dst_port)
                    except:
                        packet_info["source_port"] = src_port
                        packet_info["dest_port"] = dst_port

            # 提取協議和標誌
            if "TCP" in line:
                packet_info["protocol"] = "TCP"
                # 提取TCP標誌
                flags_pattern = re.compile(r'Flags \[([^\]]+)\]')
                flags_match = flags_pattern.search(line)
                if flags_match:
                    packet_info["tcp_flags"] = flags_match.group(1)

                # 提取序列號
                seq_pattern = re.compile(r'seq (\d+):(\d+)')
                seq_match = seq_pattern.search(line)
                if seq_match:
                    start_seq, end_seq = seq_match.groups()
                    packet_info["seq_start"] = int(start_seq)
                    packet_info["seq_end"] = int(end_seq)
                    packet_info["length"] = int(end_seq) - int(start_seq)

            elif "UDP" in line:
                packet_info["protocol"] = "UDP"
                # 提取UDP長度
                length_pattern = re.compile(r'UDP, length (\d+)')
                length_match = length_pattern.search(line)
                if length_match:
                    packet_info["length"] = int(length_match.group(1))

            # 提取HTTP信息（如果有）
            if "HTTP" in line:
                packet_info["application_protocol"] = "HTTP"
                http_pattern = re.compile(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS) ([^ ]+) HTTP')
                http_match = http_pattern.search(line)
                if http_match:
                    method, path = http_match.groups()
                    packet_info["http"] = {
                        "method": method,
                        "path": path
                    }

            return packet_info
        except Exception as e:
            self.logger.error(f"Error parsing tcpdump line: {str(e)}")
            self.logger.error(f"Problematic line: {line}")
            import traceback
            self.logger.error(traceback.format_exc())
            return {"raw_output": line.strip(),
                    "source_ip": "parse_error",
                    "source_port": 0,
                    "dest_ip": "parse_error",
                    "dest_port": 0}

    def save_packet_json(self, packet_info):
        """將封包信息保存為JSON文件"""
        try:
            # 生成文件名
            timestamp = packet_info.get('timestamp', datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))
            timestamp = timestamp.replace(':', '-').replace(' ', '_')
            filename = f"{self.json_dir}/packet_{timestamp}.json"

            # 寫入文件
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(packet_info, f, ensure_ascii=False, indent=2)

        except Exception as e:
            self.logger.error(f"Error saving JSON file: {str(e)}")

    def start_monitoring(self):
        """開始監聽封包"""
        try:
            # 建立tcpdump命令
            cmd = ["sudo", "tcpdump"]

            # 添加介面選項
            if self.interface:
                cmd.extend(["-i", self.interface])
            else:
                cmd.extend(["-i", "any"])

            # 設置過濾器
            filter_parts = []

            # 添加端口過濾
            port_filters = " or ".join(f"port {port}" for port in self.ports)
            filter_parts.append(f"({port_filters})")

            # 添加源IP過濾（如果有指定）
            if self.source_ip:
                filter_parts.append(f"src host {self.source_ip}")

            # 添加源端口過濾（如果有指定）
            if self.source_ports:
                src_port_filters = " or ".join(f"src port {port}" for port in self.source_ports)
                filter_parts.append(f"({src_port_filters})")

            # 組合過濾規則
            filter_expr = " and ".join(filter_parts)

            # 添加輸出選項，使用更簡單的格式，添加時間戳
            cmd.extend(["-n", "-l", "-v", "-tttt"])  # -tttt 添加年月日時間戳

            # 添加過濾表達式
            cmd.append(filter_expr)

            # 設置終止時的清理處理
            def signal_handler(sig, frame):
                self.logger.info("\nStopping packet capture...")
                if self.tcpdump_process:
                    self.tcpdump_process.terminate()
                sys.exit(0)

            signal.signal(signal.SIGINT, signal_handler)

            # 顯示最終命令
            cmd_str = " ".join(cmd)
            self.logger.info(f"Starting tcpdump with command: {cmd_str}")
            self.logger.info("Packet capture started (press Ctrl+C to stop)...")

            # 啟動tcpdump進程
            self.tcpdump_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1  # 行緩衝
            )

            # 先嘗試讀取一次stderr，確認tcpdump開始運行
            stderr_line = self.tcpdump_process.stderr.readline()
            if stderr_line:
                self.logger.info(f"tcpdump: {stderr_line.strip()}")

            # 開始讀取stdout，捕獲封包
            packet_count = 0
            while True:
                line = self.tcpdump_process.stdout.readline()
                if not line:
                    break

                # 處理並保存封包數據
                packet_info = self.parse_tcpdump_line(line)
                if packet_info:
                    self.save_packet_json(packet_info)

                    # 顯示封包信息
                    src = f"{packet_info['source_ip']}:{packet_info['source_port']}"
                    dst = f"{packet_info['dest_ip']}:{packet_info['dest_port']}"
                    proto = packet_info.get('protocol', 'unknown')
                    pkt_time = packet_info.get('packet_timestamp', 'unknown')

                    self.logger.info(f"Packet: [{pkt_time}] {src} -> {dst} ({proto})")
                    packet_count += 1

                    # 每封包顯示一次統計
                    self.logger.info(f"Total packets captured: {packet_count}")

            # 如果沒有正確退出循環，嘗試讀取錯誤輸出
            stderr_output = self.tcpdump_process.stderr.read()
            if stderr_output:
                self.logger.error(f"tcpdump error: {stderr_output}")

            # 進程結束
            self.tcpdump_process.wait()
            self.logger.info(f"tcpdump process ended, captured {packet_count} packets")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running tcpdump: {e.output}")
            sys.exit(1)
        except FileNotFoundError:
            self.logger.error("tcpdump command not found. Please install tcpdump.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error in monitoring: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Network Packet Monitoring Tool (tcpdump-based)')
    parser.add_argument('-p', '--ports', type=str, required=True,
                        help='Ports to monitor (comma-separated, e.g., 8080,443,3306)')
    parser.add_argument('-i', '--interface', type=str, default="any",
                        help='Network interface to monitor (default: any)')
    parser.add_argument('-s', '--source', type=str, default=None,
                        help='Source IP to filter (only capture packets from this IP)')
    parser.add_argument('-sp', '--source-ports', type=str, default=None,
                        help='Source ports to filter (comma-separated, e.g., 12345,54321)')

    args = parser.parse_args()

    monitor = TCPDumpMonitor(args.ports, args.interface, args.source, args.source_ports)
    monitor.start_monitoring()


if __name__ == "__main__":
    main()
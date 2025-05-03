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


class WinDumpMonitor:
    def __init__(self, ports, interface=None, source_ip=None, source_ports=None):
        """初始化監聽器"""
        self.ports = [int(port) for port in ports.split(',')] if isinstance(ports, str) else [ports]
        self.setup_logging()

        # Windows下的網路介面通常使用不同的命名方式，可能是數字或GUID
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
        self.logger.info(f"監控端口: {self.ports}")
        if self.source_ip:
            self.logger.info(f"過濾來源IP: {self.source_ip}")
        if self.source_ports:
            self.logger.info(f"過濾來源端口: {self.source_ports}")
        self.logger.info(f"JSON封包將保存在: {os.path.abspath(self.json_dir)}")
        self.logger.info(f"PCAP檔案將保存在: {os.path.abspath(self.pcap_dir)}")

        # 處理進程
        self.windump_process = None

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

    def parse_windump_line(self, line):
        """解析windump輸出行"""
        try:
            # Windows環境下可能會有不同的輸出格式
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

            # 嘗試提取完整時間戳 (當windump啟用了 -tttt 參數時)
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
            self.logger.error(f"解析windump行錯誤: {str(e)}")
            self.logger.error(f"有問題的行: {line}")
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
            self.logger.error(f"保存JSON文件錯誤: {str(e)}")

    def start_monitoring(self):
        """開始監聽封包"""
        try:
            # 建立windump命令
            # Windows環境下不需要使用sudo
            cmd = ["windump"]

            # 添加介面選項
            if self.interface:
                cmd.extend(["-i", self.interface])
            else:
                # 查找可用網路介面的命令提示
                self.logger.info("若未指定介面，建議先執行 'windump -D' 查看可用的網路介面列表")
                cmd.extend(["-i", "1"])  # Windows預設使用第一個介面

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

            # Windows中的信號處理可能有所不同
            # 設置終止時的清理處理
            def signal_handler(sig, frame):
                self.logger.info("\n停止封包捕獲...")
                if self.windump_process:
                    # Windows使用不同的終止進程方法
                    self.windump_process.terminate()
                sys.exit(0)

            # 設置信號處理器，對於CTRL+C事件
            signal.signal(signal.SIGINT, signal_handler)

            # 顯示最終命令
            cmd_str = " ".join(cmd)
            self.logger.info(f"使用命令啟動windump: {cmd_str}")
            self.logger.info("封包捕獲已開始 (按Ctrl+C停止)...")

            # 啟動windump進程
            # Windows環境中可能需要管理員權限運行
            self.windump_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1,  # 行緩衝
                creationflags=subprocess.CREATE_NO_WINDOW  # Windows特有，避免出現命令提示視窗
            )

            # 先嘗試讀取一次stderr，確認windump開始運行
            stderr_line = self.windump_process.stderr.readline()
            if stderr_line:
                self.logger.info(f"windump: {stderr_line.strip()}")

            # 開始讀取stdout，捕獲封包
            packet_count = 0
            while True:
                line = self.windump_process.stdout.readline()
                if not line:
                    break

                # 處理並保存封包數據
                packet_info = self.parse_windump_line(line)
                if packet_info:
                    self.save_packet_json(packet_info)

                    # 顯示封包信息
                    src = f"{packet_info['source_ip']}:{packet_info['source_port']}"
                    dst = f"{packet_info['dest_ip']}:{packet_info['dest_port']}"
                    proto = packet_info.get('protocol', 'unknown')
                    pkt_time = packet_info.get('packet_timestamp', 'unknown')

                    self.logger.info(f"封包: [{pkt_time}] {src} -> {dst} ({proto})")
                    packet_count += 1

                    # 每封包顯示一次統計
                    self.logger.info(f"已捕獲封包總數: {packet_count}")

            # 如果沒有正確退出循環，嘗試讀取錯誤輸出
            stderr_output = self.windump_process.stderr.read()
            if stderr_output:
                self.logger.error(f"windump錯誤: {stderr_output}")

            # 進程結束
            self.windump_process.wait()
            self.logger.info(f"windump進程已結束，共捕獲 {packet_count} 個封包")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"執行windump時發生錯誤: {e.output}")
            sys.exit(1)
        except FileNotFoundError:
            self.logger.error("找不到windump命令。請確保安裝了WinDump並設置在PATH環境變數中。")
            self.logger.info("您可以從以下位置下載WinDump: https://www.winpcap.org/windump/")
            self.logger.info("同時請安裝WinPcap: https://www.winpcap.org/")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"監控時發生錯誤: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            sys.exit(1)


def list_interfaces():
    """顯示可用的網路介面"""
    try:
        interfaces_process = subprocess.Popen(
            ["windump", "-D"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = interfaces_process.communicate()

        if stderr and not stdout:
            print(f"錯誤: {stderr}")
            return

        print("可用的網路介面:")
        print(stdout)
    except FileNotFoundError:
        print("找不到windump命令。請確保安裝了WinDump並設置在PATH環境變數中。")
        print("您可以從以下位置下載WinDump: https://www.winpcap.org/windump/")
        print("同時請安裝WinPcap: https://www.winpcap.org/")


def main():
    parser = argparse.ArgumentParser(description='Windows網路封包監控工具 (基於WinDump)')
    parser.add_argument('-p', '--ports', type=str, required=True,
                        help='要監控的端口 (以逗號分隔，例如 8080,443,3306)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='要監控的網路介面 (預設: 1，使用第一個介面)')
    parser.add_argument('-s', '--source', type=str, default=None,
                        help='要過濾的源IP (僅捕獲來自此IP的封包)')
    parser.add_argument('-sp', '--source-ports', type=str, default=None,
                        help='要過濾的源端口 (以逗號分隔，例如 12345,54321)')
    parser.add_argument('-l', '--list-interfaces', action='store_true',
                        help='列出所有可用的網路介面')

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    monitor = WinDumpMonitor(args.ports, args.interface, args.source, args.source_ports)
    monitor.start_monitoring()


if __name__ == "__main__":
    main()

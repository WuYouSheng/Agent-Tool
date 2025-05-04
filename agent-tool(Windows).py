#!/usr/bin/env python3
import subprocess
import sys
import os
import re
import json
import argparse
import logging
import time
import datetime
import signal
import base64
from collections import deque


class WinDumpMonitor:
    def __init__(self, ports, interface=None, source_ip=None, source_ports=None):
        """初始化監聽器"""
        self.ports = [int(port) for port in ports.split(',')] if isinstance(ports, str) else [ports]  # str 轉 int
        self.setup_logging()  # 啟動log 紀錄

        # Windows 網卡介面通常是數字格式
        self.interface = interface
        self.source_ip = source_ip

        # 處理源端口
        if source_ports:
            if isinstance(source_ports, str) and ',' in source_ports:
                self.source_ports = [int(p) for p in source_ports.split(',')]
            else:
                self.source_ports = [int(source_ports)]
        else:
            self.source_ports = []

        # 建立資料儲存目錄 (Windows路徑格式)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.json_dir = os.path.join(current_dir, "json_packets")
        self.pcap_dir = os.path.join(current_dir, "captures")
        os.makedirs(self.json_dir, exist_ok=True)
        os.makedirs(self.pcap_dir, exist_ok=True)

        # 顯示設定訊息
        self.logger.info(f"Monitoring ports: {self.ports}")
        if self.source_ip:
            self.logger.info(f"Filtering by source IP: {self.source_ip}")
        if self.source_ports:
            self.logger.info(f"Filtering by source ports: {self.source_ports}")
        self.logger.info(f"JSON packets will be saved in: {os.path.abspath(self.json_dir)}")
        self.logger.info(f"PCAP files will be saved in: {os.path.abspath(self.pcap_dir)}")

        # 處理進程
        self.windump_process = None

        # FPS 計算相關
        self.packet_times = deque(maxlen=100)  # 儲存最近100個封包的時間戳
        self.last_fps_update = time.time()
        self.fps = 0
        self.fps_update_interval = 1.0  # 每1秒更新一次FPS

    def setup_logging(self):
        """設置日誌記錄"""
        log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'packet_monitor.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def parse_windump_line(self, line):
        """解析WinDump輸出行"""
        try:
            # 移除 ANSI 控制碼
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

            # 嘗試提取完整時間戳 (當WinDump啟用了 -tttt 參數時)
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
            self.logger.error(f"Error parsing WinDump line: {str(e)}")
            self.logger.error(f"Problematic line: {line}")
            import traceback
            self.logger.error(traceback.format_exc())
            return {"raw_output": line.strip(),
                    "source_ip": "parse_error",
                    "source_port": 0,
                    "dest_ip": "parse_error",
                    "dest_port": 0}

    def should_save_packet(self, packet_info):
        """檢查封包是否符合過濾條件，只保留匹配的IP和端口"""
        # 檢查是否符合源IP過濾條件（如果有指定）
        if self.source_ip and packet_info['source_ip'] != self.source_ip:
            return False

        # 檢查是否符合源端口過濾條件（如果有指定）
        if self.source_ports and packet_info['source_port'] not in self.source_ports:
            return False

        # 檢查是否符合目標端口過濾條件
        if packet_info['dest_port'] not in self.ports:
            return False

        # 如果以上條件都通過，則該封包符合保存條件
        return True

    def save_packet_json(self, packet_info):
        """將封包信息保存為JSON文件"""
        try:
            # 生成文件名
            timestamp = packet_info.get('packet_timestamp', datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))
            timestamp = timestamp.replace(':', '-').replace(' ', '_')
            filename = os.path.join(self.json_dir, f"packet_{timestamp}.json")

            # 寫入文件
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(packet_info, f, ensure_ascii=False, indent=2)

        except Exception as e:
            self.logger.error(f"Error saving JSON file: {str(e)}")

    def update_fps(self):
        """計算並更新FPS值"""
        now = time.time()

        # 添加當前時間戳到隊列
        self.packet_times.append(now)

        # 檢查是否應該計算並顯示FPS
        if now - self.last_fps_update >= self.fps_update_interval:
            # 如果隊列中有足夠的包，計算FPS
            if len(self.packet_times) > 1:
                time_span = self.packet_times[-1] - self.packet_times[0]
                if time_span > 0:
                    self.fps = (len(self.packet_times) - 1) / time_span
                    self.logger.info(f"Current Stream FPS: {self.fps:.2f}")

            self.last_fps_update = now

        return self.fps

    def start_monitoring(self):
        """開始監聽封包"""
        try:
            # Windows需要指定WinDump完整路徑，假設WinDump.exe在當前目錄或PATH中
            windump_path = "WinDump.exe"

            # 建立WinDump命令
            cmd = [windump_path]

            # 添加介面選項
            if self.interface:
                cmd.extend(["-i", self.interface])
            else:
                cmd.extend(["-i", "1"])  # Windows默認使用介面1，請根據實際情況修改

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

            # Windows處理Ctrl+C方式不同，嘗試設置處理器
            def windows_signal_handler(sig, frame):
                self.logger.info("\nStopping packet capture...")
                if self.windump_process:
                    try:
                        # Windows上更可靠的終止進程方式
                        import ctypes
                        kernel32 = ctypes.WinDLL('kernel32')
                        handle = kernel32.OpenProcess(1, 0, self.windump_process.pid)
                        kernel32.TerminateProcess(handle, 0)
                        kernel32.CloseHandle(handle)
                    except:
                        self.windump_process.terminate()
                sys.exit(0)

            # 在Windows上設置信號處理
            try:
                signal.signal(signal.SIGINT, windows_signal_handler)
                signal.signal(signal.SIGTERM, windows_signal_handler)
            except (AttributeError, ValueError):
                self.logger.warning("Could not set up signal handlers properly on Windows.")

            # 顯示最終命令
            cmd_str = " ".join(cmd)
            self.logger.info(f"Starting WinDump with command: {cmd_str}")
            self.logger.info("Packet capture started (press Ctrl+C to stop)...")

            # 啟動WinDump進程
            # 注意：Windows可能需要管理員權限來運行WinDump
            try:
                self.windump_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1,  # 行緩衝
                    creationflags=subprocess.CREATE_NO_WINDOW  # Windows特有，不顯示命令窗口
                )
            except AttributeError:
                # 如果CREATE_NO_WINDOW不可用，嘗試普通方式啟動
                self.windump_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1  # 行緩衝
                )

            # 先嘗試讀取一次stderr，確認WinDump開始運行
            try:
                stderr_line = self.windump_process.stderr.readline()
                if stderr_line:
                    self.logger.info(f"WinDump: {stderr_line.strip()}")
            except Exception as e:
                self.logger.warning(f"Could not read stderr: {str(e)}")

            # 開始讀取stdout，捕獲封包
            packet_count = 0
            saved_count = 0

            while True:
                try:
                    line = self.windump_process.stdout.readline()
                    if not line:
                        break

                    # 處理封包數據
                    packet_info = self.parse_windump_line(line)
                    if packet_info:
                        packet_count += 1

                        # 檢查是否符合保存條件
                        if self.should_save_packet(packet_info):
                            # 更新FPS計算
                            current_fps = self.update_fps()
                            packet_info["fps"] = current_fps

                            # 保存符合條件的封包
                            self.save_packet_json(packet_info)
                            saved_count += 1

                            # 顯示封包信息
                            src = f"{packet_info['source_ip']}:{packet_info['source_port']}"
                            dst = f"{packet_info['dest_ip']}:{packet_info['dest_port']}"
                            proto = packet_info.get('protocol', 'unknown')
                            pkt_time = packet_info.get('packet_timestamp', 'unknown')

                            self.logger.info(f"Saved Packet: [{pkt_time}] {src} -> {dst} ({proto})")

                        # 每10個封包顯示一次統計
                        if packet_count % 10 == 0:
                            self.logger.info(f"Total packets captured: {packet_count}, Saved: {saved_count}")
                except KeyboardInterrupt:
                    # 在Windows上特別處理Ctrl+C
                    self.logger.info("\nStopping packet capture (keyboard interrupt)...")
                    break
                except Exception as e:
                    self.logger.error(f"Error processing packet: {str(e)}")
                    import traceback
                    self.logger.error(traceback.format_exc())
                    # 繼續捕獲，不中斷

            # 如果沒有正確退出循環，嘗試讀取錯誤輸出
            try:
                stderr_output = self.windump_process.stderr.read()
                if stderr_output:
                    self.logger.error(f"WinDump error: {stderr_output}")
            except:
                pass

            # 進程結束
            try:
                self.windump_process.terminate()
                self.windump_process.wait(timeout=5)
            except:
                pass

            self.logger.info(f"WinDump process ended, captured {packet_count} packets, saved {saved_count} packets")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running WinDump: {e.output}")
            sys.exit(1)
        except FileNotFoundError:
            self.logger.error(
                "WinDump.exe not found. Please ensure WinDump is installed and in the PATH or current directory.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error in monitoring: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            sys.exit(1)


def list_interfaces():
    """列出所有可用的網絡介面"""
    try:
        # 執行WinDump -D來列出所有介面
        result = subprocess.run(["WinDump.exe", "-D"], capture_output=True, text=True)
        if result.returncode == 0:
            print("Available network interfaces:")
            print(result.stdout)
        else:
            print("Error listing interfaces:")
            print(result.stderr)
    except FileNotFoundError:
        print("WinDump.exe not found. Please ensure WinDump is installed and in the PATH or current directory.")
    except Exception as e:
        print(f"Error listing interfaces: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Network Packet Monitoring Tool (WinDump-based)')
    parser.add_argument('-p', '--ports', type=str, required=True,
                        help='Ports to monitor (comma-separated, e.g., 8080,443,3306)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Network interface to monitor (default: 1)')
    parser.add_argument('-s', '--source', type=str, default=None,
                        help='Source IP to filter (only capture packets from this IP)')
    parser.add_argument('-sp', '--source-ports', type=str, default=None,
                        help='Source ports to filter (comma-separated, e.g., 12345,54321)')
    parser.add_argument('-l', '--list-interfaces', action='store_true',
                        help='List available network interfaces and exit')

    args = parser.parse_args()

    # 如果要列出介面，則列出後退出
    if args.list_interfaces:
        list_interfaces()
        return

    # 如果未指定介面，使用默認值1
    if args.interface is None:
        args.interface = "1"
        print("No interface specified, using default interface 1.")
        print("Use -l to list available interfaces or -i to specify an interface.")

    monitor = WinDumpMonitor(args.ports, args.interface, args.source, args.source_ports)
    monitor.start_monitoring()


if __name__ == "__main__":
    main()
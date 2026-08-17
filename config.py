# config.py
import os

# 目标网络
TARGET_NETWORK = "192.168.1.0/24"

# 扫描参数
PING_TIMEOUT = 0.1          # ping 超时（秒）
PORT_SCAN_TIMEOUT = 0.5     # 端口连接超时（秒）
IP_SCAN_THREADS = 50        # IP 扫描并发线程数
PORT_SCAN_THREADS = 100     # 端口扫描并发线程数
BRUTE_THREADS = 20          # 爆破并发线程数

# 字典相关
DICT_DIR = "dictionaries"
os.makedirs(DICT_DIR, exist_ok=True)

# 协议对应的字典文件名
PROTOCOL_DICT_FILES = {
    "ssh": "ssh_dict.txt",
    "ftp": "ftp_dict.txt",
    "mysql": "mysql_dict.txt",
    "redis": "redis_dict.txt",
    "rdp": "rdp_dict.txt",
    "smb": "smb_dict.txt",
    "http": "http_dict.txt",
    "https": "https_dict.txt",
}

DICT_DIR = "dictionaries"
os.makedirs(DICT_DIR, exist_ok=True)

RESULT_DIR = "results"
os.makedirs(RESULT_DIR, exist_ok=True)
RESULT_CSV = os.path.join(RESULT_DIR, "brute_results.csv")

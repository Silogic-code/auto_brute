class scan_tools:
    def __init__(self, network):
        self.network = network
        self.cidr = self.network.split("/")[-1]
        ip_part = self.network.split("/")[0]
        self.net_prefix = ".".join(ip_part.split(".")[:3])
        self.maxn = calc_tools.get_usable_host(int(self.cidr))

    # ========== [并发改动] 扫描单个IP（供线程池调用） ==========
    def _ping_single_ip(self, ip, timeout=0):
        """线程池调用的单IP探测函数"""
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "100", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            handle_msg.handle_ip_msg(ip)
            return ip
        elif result.returncode == 1:
            handle_msg.handle_err_msg(f"{ip} 无响应")
        else:
            handle_msg.handle_err_msg(f"{ip} 探测异常，返回码:{result.returncode}")
        return None

    # ========== [并发改动] IP扫描（多线程） ==========
    def scan_ip(self, timeout=0, max_workers=50):
        """
        多线程并发 ping 扫描网段
        max_workers: 并发线程数，默认 50，可根据网络环境调整
        """
        alive_list = []
        # 生成所有待扫描 IP
        ip_list = [f"{self.net_prefix}.{i}" for i in range(1, self.maxn + 1)]

        # 使用线程池并发执行
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_ip = {executor.submit(self._ping_single_ip, ip, timeout): ip for ip in ip_list}
            # 收集结果
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    alive_list.append(result)
        return alive_list

    # ========== [并发改动] 扫描单个端口（供线程池调用） ==========
    def _scan_single_port(self, target, port, timeout):
        """线程池调用的单端口探测函数"""
        service_map = {
            22: "SSH", 80: "HTTP", 443: "HTTPS",
            5000: "Flask", 5050: "Flask", 8000: "Flask",
            3306: "MySQL", 6379: "Redis", 3389: "RDP",
            445: "SMB", 21: "FTP", 23: "Telnet",
            25: "SMTP", 53: "DNS", 110: "POP3",
            143: "IMAP", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 5432: "PostgreSQL", 5900: "VNC",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = s.connect_ex((target, port))
            s.close()
            if res == 0:
                label = service_map.get(port, "")
                with print_lock:
                    if label:
                        handle_msg.handle_port_msg(f"{port} 开放 [{label}]")
                    else:
                        handle_msg.handle_port_msg(f"{port} 开放")
                return port
            elif res == 111:
                with print_lock:
                    handle_msg.handle_err_msg(f"{port} 端口关闭")
            else:
                with print_lock:
                    handle_msg.handle_err_msg(f"{port} 探测异常")
        except Exception as e:
            with print_lock:
                handle_msg.handle_err_msg(f"{port} 扫描异常", e)
        return None

    # ========== [并发改动] 端口扫描（多线程） ==========
    def scan_ports(self, target, port_list, timeout=0.5, max_workers=100):
        """
        多线程并发扫描端口
        max_workers: 并发线程数，默认 100
        """
        open_list = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(self._scan_single_port, target, port, timeout): port
                for port in port_list
            }
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_list.append(result)
        return open_list

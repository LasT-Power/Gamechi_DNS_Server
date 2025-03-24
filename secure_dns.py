# -*- coding: utf-8 -*-
import os
import json
import socket
import hashlib
import threading
from cryptography.fernet import Fernet
from colorama import Fore, Style, init
import warnings
import base64
import time
import random

# غیرفعال کردن هشدارها
warnings.filterwarnings("ignore", category=SyntaxWarning)
init()

class SecureDNS:
    def __init__(self):
        self.key = self.generate_key()
        self.cipher = Fernet(self.key)
        self.dns_cache = {}
        self.load_config()
        
    def generate_key(self):
        """تولید کلید رمزنگاری"""
        return Fernet.generate_key()
    
    def load_config(self):
        """بارگذاری تنظیمات از فایل"""
        try:
            with open('config.json') as f:
                self.config = json.load(f)
        except:
            self.config = {
                "dns_servers": ["1.1.1.1", "8.8.8.8"],
                "obfuscation": True,
                "port": 5353
            }
    
    def encrypt(self, data):
        """رمزنگاری داده‌ها"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, data):
        """رمزگشایی داده‌ها"""
        return self.cipher.decrypt(data.encode()).decode()
    
    def obfuscate_packet(self, packet):
        """استتار پکت DNS"""
        if self.config["obfuscation"]:
            return base64.b85encode(packet).decode() + str(random.randint(1000,9999))
        return packet
    
    def deobfuscate_packet(self, packet):
        """بازیابی پکت اصلی"""
        if self.config["obfuscation"]:
            return base64.b85decode(packet[:-4])
        return packet
    
    def resolve_domain(self, domain):
        """حل DNS با رمزنگاری و استتار"""
        try:
            # اگر در کش وجود داشت
            if domain in self.dns_cache:
                if time.time() - self.dns_cache[domain]['timestamp'] < 300:
                    return self.dns_cache[domain]['ip']
            
            # ایجاد پکت DNS دستی
            query = self.create_dns_query(domain)
            obfuscated = self.obfuscate_packet(query)
            
            # ارسال به سرورهای DNS
            for dns_server in self.config["dns_servers"]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(obfuscated.encode(), (dns_server, 53))
                        response = s.recv(1024)
                        ip = self.parse_dns_response(self.deobfuscate_packet(response))
                        if ip:
                            self.dns_cache[domain] = {
                                'ip': ip,
                                'timestamp': time.time()
                            }
                            return ip
                except:
                    continue
            return None
        except Exception as e:
            print(f"{Fore.RED}Error in DNS resolution: {e}{Style.RESET_ALL}")
            return None

    def create_dns_query(self, domain):
        """ساخت پکت DNS دستی"""
        # پیاده‌سازی ساده پکت DNS
        packet = bytearray()
        # هدر DNS
        packet.extend(bytes([0xAB, 0xCD]))  # ID
        packet.extend(bytes([0x01, 0x00]))  # Flags
        packet.extend(bytes([0x00, 0x01]))  # تعداد سوالات
        packet.extend(bytes([0x00, 0x00]))  # پاسخ‌ها
        packet.extend(bytes([0x00, 0x00]))  # Authority
        packet.extend(bytes([0x00, 0x00]))  # Additional
        
        # بخش سوال
        for part in domain.split('.'):
            packet.append(len(part))
            packet.extend(part.encode())
        packet.append(0x00)  # پایان دامنه
        packet.extend(bytes([0x00, 0x01]))  # نوع A
        packet.extend(bytes([0x00, 0x01]))  # کلاس IN
        
        return packet

    def parse_dns_response(self, response):
        """پارس پاسخ DNS"""
        try:
            # این یک پیاده‌سازی ساده است
            # در عمل باید پکت DNS را به درستی پارس کنید
            return ".".join(map(str, response[-4:]))
        except:
            return None

def show_banner():
    print( f"      {Fore.MAGENTA}                                   In The name of God\n")
    print( f"      {Fore.YELLOW}                                   ①②③④⑤⑥⑦⑧⑨⑩\n")
    print(f"\n")
    print(f"                   {Fore.BLUE}{Fore.RED}▪{Fore.RED}-----------------------------------------------------------------------------------{Fore.RED}▪{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN} ______   _        _______    _______  _______  _______           _______  _______ {Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN}(  __  \ ( (    /|(  ____ \  (  ____ \(  ____ \(  ____ )|\     /|(  ____ \(  ____ ){Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN}| (  \  )|  \  ( || (    \/  | (    \/| (    \/| (    )|| )   ( || (    \/| (    )|{Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN}| |   ) ||   \ | || (_____   | (_____ | (__    | (____)|| |   | || (__    | (____)|{Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN}| |   | || (\ \) |(_____  )  (_____  )|  __)   |     __)( (   ) )|  __)   |     __){Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN}| |   ) || | \   |      ) |        ) || (      | (\ (    \ \_/ / | (      | (\ (   {Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN}| (__/  )| )  \  |/\____) |  /\____) || (____/\| ) \ \__  \   /  | (____/\| ) \ \__{Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.GREEN}(______/ |/    )_)\_______)  \_______)(_______/|/   \__/   \_/   (_______/|/   \__/{Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.BLUE}          __              ___  __                 __   __        __   ___          {Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.BLUE}         / _`  /\   |\/| |__  /  ` |__| |        /__` |__)  /\  /  ` |__           {Fore.RED}¦{Style.RESET_ALL}")
    print(rf"                   {Fore.RED}¦{Fore.BLUE}         \__> /~~\  |  | |___ \__, |  | |    .   .__/ |    /~~\ \__, |___          {Fore.RED}¦{Style.RESET_ALL}")
    print(f"                   {Fore.BLUE}{Fore.RED}▪{Fore.RED}-----------------------------------------------------------------------------------{Fore.RED}▪{Style.RESET_ALL}\n"
    f"\n"
    
    f" □■▪▫▴₯₭₿◂▲¦ \n"
    f"{Fore.GREEN}       ■     ©2024 All Copy Rite by Gamechi.Space {Style.RESET_ALL}\n"
)
if __name__ == "__main__":
    show_banner()
    dns = SecureDNS()
    
    while True:
        domain = input(f"{Fore.CYAN}Enter domain to resolve (or 'exit' to quit): {Style.RESET_ALL}")
        if domain.lower() == 'exit':
            break
            
        ip = dns.resolve_domain(domain)
        if ip:
            print(f"{Fore.GREEN}Resolved {domain} to {ip}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to resolve {domain}{Style.RESET_ALL}")
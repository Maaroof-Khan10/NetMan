#!/usr/bin/env python3

import argparse
import string
import ipaddress
import logging
import sys
import time
from typing import Dict, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.markup import escape
from scapy.all import ARP, ICMP, IP, Ether, srp, sr1

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

console = Console()


def get_vendor(mac: str) -> str:
    """
    Fetches the vendor information for a given MAC address using an external API.
    
    Args:
        mac (str): The MAC address to look up.
        
    Returns:
        str: The vendor name, or an error/unknown status.
    """
    try:
        # The API can be slow, so a longer timeout is reasonable here.
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return "[yellow]Unknown Vendor[/yellow]"
    except requests.RequestException:
        return "[red]API Error[/red]"


def guess_os(ip_address: str) -> str:
    """
    Guesses the operating system based on the TTL of an ICMP echo reply.

    Args:
        ip_address (str): The IP address to ping.
        
    Returns:
        str: A string guessing the OS (e.g., "Linux", "Windows").
    """
    try:
        reply = sr1(IP(dst=ip_address) / ICMP(), timeout=2, verbose=False)
        if reply is None:
            return "[yellow]No ICMP Response[/yellow]"
        elif reply.haslayer(ICMP):
            ttl = reply.ttl
            if ttl <= 64:
                return "🐧 Linux / Unix"
            elif ttl <= 128:
                return "🪟 Windows"
            else:
                return "Router / Other"
        else:
            return "[yellow]Unknown[/yellow]"
    except Exception:
        return "[red]Error[/red]"
    
def get_mac_from_raw_packet(packet) -> str:
    """
    Manually extracts and sanitizes the source MAC address from the raw bytes
    of an Ethernet frame. This is the most robust method possible.
    """
    try:
        raw_bytes = packet.original
        mac_bytes = raw_bytes[6:12]
        mac_str = "-".join(f"{b:02x}" for b in mac_bytes)
        valid_chars = string.hexdigits + "-"
        sanitized_mac = "".join(filter(lambda char: char in valid_chars, mac_str))
        return sanitized_mac
    except Exception:
        return "[red]MAC Parse Error[/red]"


def discover_devices(ip_range: str, scan_count: int, scan_timeout: int, progress: Progress) -> Dict[str, str]:
    """
    Performs multiple ARP scans to discover devices on the network.

    Args:
        ip_range (str): The IP range in CIDR notation (e.g., "192.168.1.1/24").
        scan_count (int): The number of times to scan the network.
        scan_timeout (int): The timeout in seconds for each ARP scan.
        progress (Progress): A rich.progress.Progress object for updating the UI.

    Returns:
        Dict[str, str]: A dictionary mapping discovered IP addresses to MAC addresses.
    """
    discovered_devices = {}
    scan_task = progress.add_task("[cyan]Scanning network...", total=scan_count)

    for i in range(scan_count):
        progress.update(scan_task, description=f"[cyan]Scanning network (Pass {i+1}/{scan_count})...")
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list, _ = srp(arp_request_broadcast, timeout=scan_timeout, verbose=False)

        for sent, received in answered_list:
            mac_address = get_mac_from_raw_packet(received)
            discovered_devices[received.psrc] = mac_address
        
        progress.update(scan_task, advance=1)
        if i < scan_count - 1:
            time.sleep(1)

    progress.update(scan_task, description="[green]Scan Complete.")
    return discovered_devices


def validate_ip_range(value: str) -> str:
    """Argparse type validator for IP range."""
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid IP range in CIDR notation (e.g., 192.168.1.1/24).")


def main():
    """
    Main function to parse arguments and run the network scanner.
    """
    parser = argparse.ArgumentParser(
        description="An ARP based network scanner to discover devices on a local network.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("ip_range", type=validate_ip_range, help="The IP range to scan in CIDR notation (e.g., '192.168.1.1/24').")
    parser.add_argument("-s", "--scans", type=int, default=5, help="The number of scan iterations to perform (default: 5).")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout in seconds for each ARP scan (default: 2).")

    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold cyan]NetMan[/bold cyan]\n:satellite: A ARP based network scanner.\n",
        border_style="green"
    ))
    console.print(f"[info]Scan Parameters:[/info]")
    console.print(f"  [bold]Target Range[/bold]: {args.ip_range}")
    console.print(f"  [bold]Scan Count[/bold]:   {args.scans}")
    console.print(f"  [bold]Timeout[/bold]:      {args.timeout}s\n")

    try:
        with Progress(console=console) as progress:
            devices = discover_devices(args.ip_range, args.scans, args.timeout, progress)

            if not devices:
                console.print("\n[bold red]No devices found.[/bold red] Try a different IP range or run with sudo.")
                sys.exit(0)

            table = Table(title=f"\n[bold]Discovered Devices ({len(devices)})[/bold]", show_header=True, header_style="bold magenta")
            table.add_column("IP Address", style="cyan", no_wrap=True)
            table.add_column("MAC Address", style="green")
            table.add_column("Vendor", style="yellow")
            table.add_column("OS (Guess)", style="blue")

            analysis_task = progress.add_task("[cyan]Analyzing devices...", total=len(devices))

            sorted_ips = sorted(devices.keys(), key=lambda ip: ipaddress.ip_address(ip))

            for ip in sorted_ips:
                mac = devices[ip][:17]
                vendor = get_vendor(mac)
                os_guess = guess_os(ip)
                table.add_row(ip, escape(mac), vendor, os_guess)
                progress.update(analysis_task, advance=1)

        console.print(table)

    except PermissionError:
        console.print("\n[bold red]Permission Error:[/bold red] This script requires root privileges to send ARP packets.")
        console.print("Please try running with 'sudo'.")
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Scan interrupted by user. Exiting.[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")


if __name__ == "__main__":
    main()
# NetMan: An ARP-Based Network Scanner 📡

Discover devices on your local network with a beautiful and informative terminal interface. `NetMan` is a lightweight, ARP-based network scanner written in Python that provides key information about connected devices, including their IP address, MAC address, vendor, and a guess at their operating system.

![UI Image](https://github.com/Maaroof-Khan10/NetMan/blob/ab1d4a9542917e1de031efaa7463ae7ba9cf8fc4/Screenshot%202025-07-21%20212609.png)

## ✨ Features

*   **🌐 ARP-Based Discovery:** Quickly and efficiently finds active devices on your local network using ARP requests.
*   **🏭 MAC Vendor Lookup:** Automatically queries the `macvendors.com` API to identify the manufacturer of each device's network hardware.
*   **🕵️ OS Guessing:** Performs a simple ICMP-based TTL analysis to provide an educated guess of the device's operating system (e.g., Windows, Linux).
*   **📊 Sleek CLI:** Leverages the `rich` library to present data in a clean, colorful, and easy-to-read table with progress bars.
*   **⚙️ Customizable Scans:** Easily adjust the number of scan passes and the timeout for more reliable results on different networks.

## 🛠️ Installation

`NetMan` requires Python 3 and a few external libraries. The setup process varies slightly between Linux and Windows.

### Prerequisites

*   **Python 3.11+**
*   **pip** (Python's package installer)
*   **Git** (to clone the repository)

### Setup Instructions

**1. Clone the Repository**

First, clone this repository to your local machine:

```bash
git clone https://github.com/Maaroof-Khan10/NetMan.git
cd NetMan
```

**2. Install Dependencies**

Follow the instructions for your operating system.

---

### 🐧 For Linux (Debian, Ubuntu, etc.)

On Linux, you need to ensure you have the necessary permissions to send raw network packets.

1.  **Install Python dependencies:** You may need to use `pip3` and `sudo` depending on your environment.
    
    ```bash
    pip3 install -r requirements.txt
    ```
2.  **Run the script with `sudo`:** Raw packet manipulation requires root privileges.
    
    ```bash
    sudo python3 netman.py <your_ip_range>
    ```

### 🪟 For Windows

On Windows, `scapy` has an additional dependency called `Npcap` for packet capturing.

1.  **Install Npcap:**
    *   Download the latest `Npcap` installer from the [official Npcap website](https://npcap.com/#download).
    *   Run the installer. **During installation, make sure to check the box for "Install Npcap in WinPcap API-compatible Mode".**

2.  **Install Python dependencies:**
    *   Open **Command Prompt** or **PowerShell as an Administrator** (Right-click the icon -> "Run as administrator"). This is crucial for the script to function correctly.
    *   Navigate to the project directory and install the required packages:
    
      ```powershell
      pip install -r requirements.txt
      ```

3.  **Run the script:**
    *   From your **Administrator** terminal, run the script:
    
      ```powershell
      python netman.py <your_ip_range>
      ```

## 🚀 Usage

`NetMan` runs from the command line. You must provide the IP range you want to scan in CIDR notation.

```bash
# Display the help menu and options
python netman.py --help
```

**Output:**

```
usage: netman.py [-h] [-s SCANS] [-t TIMEOUT] ip_range

An ARP based network scanner to discover devices on a local network.

positional arguments:
  ip_range              The IP range to scan in CIDR notation (e.g., '192.168.1.1/24').

options:
  -h, --help            show this help message and exit
  -s SCANS, --scans SCANS
                        The number of scan iterations to perform (default: 5).
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds for each ARP scan (default: 2).
```

### Examples

**Basic Scan**

Scan the `192.168.1.0/24` network with default settings (5 scan passes, 2-second timeout).

*   On Linux:
  
    ```bash
    sudo python3 netman.py 192.168.1.1/24
    ```
*   On Windows (in an Administrator terminal):
  
    ```bash
    python netman.py 192.168.1.1/24
    ```

**Advanced Scan**

Perform a more thorough scan with 10 passes and a 3-second timeout. This can be useful on slower or less reliable networks.

*   On Linux:
  
    ```bash
    sudo python3 netman.py 192.168.1.1/24 -s 10 -t 3
    ```
    or
    
    ```bash
    sudo python3 netman.py 192.168.1.1/24 --scans 10 --timeout 3
    ```
*   On Windows (in an Administrator terminal):
  
    ```bash
    python netman.py 192.168.1.1/24 -s 10 -t 3
    ```
    or
    
    ```bash
    python netman.py 192.168.1.1/24 --scans 10 --timeout 3
    ```

## 🧠 How It Works

1.  **ARP Scan:** The script constructs and broadcasts ARP "who-has" packets to every possible IP address within the specified CIDR range. Active devices respond with their IP and MAC addresses.
2.  **OS Guessing (TTL Analysis):** For each discovered device, an ICMP echo request (a ping) is sent. The `Time To Live` (TTL) value in the reply can suggest the sender's operating system, as different OSs use different default starting TTLs:
    *   **TTL <= 64:** Typically Linux, Unix, or macOS systems.
    *   **TTL <= 128:** Typically Windows systems.
3.  **Vendor Lookup:** The OUI (the first 3 bytes) of the MAC address is sent to the `macvendors.com` API to retrieve the hardware manufacturer.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/Maaroof-Khan10/NetMan/issues).

## 📄 License

This project is licensed under the MIT License - see the [`LICENSE`](https://github.com/Maaroof-Khan10/NetMan/LICENSE) file for details.

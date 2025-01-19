# PRODIGY_CS_05

## Network Packet Analyzer

### Description

The **Network Packet Analyzer Tool** is a graphical user interface (GUI) application built using **Tkinter** and **Scapy**. It allows users to capture and analyze network packets in real-time. The application displays detailed information about each captured packet, including source and destination IP/MAC addresses, protocol (TCP, UDP, ICMP), and payload details. It provides control buttons to start, stop, pause, and resume packet sniffing.

---

### Features

- **Start Sniffing**: Begin capturing network packets.
- **Stop Sniffing**: Stop packet capturing and display the message "Sniffing Stopped."
- **Pause Sniffing**: Pause the packet capture without stopping it completely.
- **Resume Sniffing**: Resume packet capture after pausing.
- **Packet Display**: Real-time display of captured packets with detailed information about each packet, including:
  - Ethernet Layer (MAC addresses)
  - IP Layer (Source and Destination IP, TTL)
  - TCP/UDP Layer (Ports, Sequence Number, Acknowledgment, Flags)
  - ICMP Layer (Type, Code)
  - Payload (First 50 bytes)
  - Packet Size and Timestamp
- **Packet Count**: Display the total number of packets captured during the session.

---

### How to Use

1. **Start Sniffing**: Click the "Start Sniffing" button to begin capturing network packets.
2. **Pause Sniffing**: Click the "Pause Sniffing" button to pause the packet capture. You can resume sniffing using the "Resume Sniffing" button.
3. **Stop Sniffing**: Click the "Stop Sniffing" button to stop the packet capture and display the status as "Sniffing Stopped."

---

### Requirements

To run this application, you need the following:

- Python 3.x
- Scapy library for packet sniffing
  - You can install Scapy using the command: 
    ```bash
    pip install scapy
    ```   

---

### Installation

1.  Clone the repository:
   ```bash
   git clone https://github.com/MAvinash24/PRODIGY_CS_05.git
   ```
    
2.  Navigate to project directory:
   ```bash
   cd PRODIGY_CS_05
   ```

3.  Run the tool:
   ```bash
   python packet_analyzer.py
   ```

---

### Screenshot of GUI
   
![Network Packet Analyzer GUI](https://github.com/user-attachments/assets/7bdb1ab7-1648-4a38-ab9f-63f71ca04ba1)

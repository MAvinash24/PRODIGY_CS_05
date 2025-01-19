import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
import threading
import queue
import time
import sys

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("800x500")

        self.packet_display = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20, state=tk.DISABLED)
        self.packet_display.pack(pady=10)

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing, width=15)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)

        self.stop_button = tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, width=15, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)

        self.pause_button = tk.Button(button_frame, text="Pause Sniffing", command=self.pause_sniffing, width=15, state=tk.DISABLED)
        self.pause_button.grid(row=1, column=0, padx=5, pady=5)

        self.resume_button = tk.Button(button_frame, text="Resume Sniffing", command=self.resume_sniffing, width=15, state=tk.DISABLED)
        self.resume_button.grid(row=1, column=1, padx=5, pady=5)

        self.packet_count_label = tk.Label(self.root, text="Packets Captured: 0", anchor='e', width=25)
        self.packet_count_label.pack(side=tk.BOTTOM, anchor='se', padx=10, pady=5)

        self.sniffing_thread = None
        self.stop_sniffing_flag = threading.Event()
        self.paused = False
        self.packet_count = 0
        self.packet_queue = queue.Queue()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing) 

    def start_sniffing(self):
        """Start sniffing network packets."""
        self.packet_display.config(state=tk.NORMAL)
        self.packet_display.delete(1.0, tk.END)  
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.NORMAL)
        self.resume_button.config(state=tk.DISABLED)
        self.paused = False
        self.packet_count = 0
        self.update_packet_count()

        self.stop_sniffing_flag.clear()
        self.sniffing_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffing_thread.start()
        self.update_gui()

    def sniff_packets(self):
        """Capture packets indefinitely."""
        print("Sniffing started...")
        try:
            sniff(prn=self.process_packet, store=0, stop_filter=self.should_stop_sniffing)
        except Exception as e:
            print(f"Error during sniffing: {e}", file=sys.stderr)

    def should_stop_sniffing(self, packet):
        """Stop sniffing when the flag is set."""
        return self.stop_sniffing_flag.is_set()

    def stop_sniffing(self):
        """Stop sniffing and reset buttons."""
        print("Stopping sniffing...")
        self.stop_sniffing_flag.set()
        if self.sniffing_thread:
            self.sniffing_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.DISABLED)
        self.resume_button.config(state=tk.DISABLED)
        self.packet_display.insert(tk.END, "Sniffing Stopped.\n")
        self.packet_display.yview(tk.END)

    def pause_sniffing(self):
        """Pause sniffing."""
        self.paused = True
        self.pause_button.config(state=tk.DISABLED)
        self.resume_button.config(state=tk.NORMAL)
        self.packet_display.insert(tk.END, "Sniffing Paused...\n")
        self.packet_display.yview(tk.END)

    def resume_sniffing(self):
        """Resume sniffing."""
        self.paused = False
        self.pause_button.config(state=tk.NORMAL)
        self.resume_button.config(state=tk.DISABLED)

    def process_packet(self, packet):
        """Process each captured packet and add it to the queue."""
        if self.paused or self.stop_sniffing_flag.is_set():
            return

        display_msg = "========= Packet Captured =========\n"
        if packet.haslayer(Ether):
            display_msg += f"[Ethernet]\n  Src MAC: {packet[Ether].src}\n  Dst MAC: {packet[Ether].dst}\n"
        if packet.haslayer(IP):
            display_msg += f"[IP]\n  Src IP: {packet[IP].src}\n  Dst IP: {packet[IP].dst}\n  TTL: {packet[IP].ttl}\n"
            if packet.haslayer(TCP):
                display_msg += (f"[TCP]\n  Src Port: {packet[TCP].sport}\n  Dst Port: {packet[TCP].dport}\n"
                                f"  Seq: {packet[TCP].seq}\n  Ack: {packet[TCP].ack}\n  Flags: {packet[TCP].flags}\n")
            elif packet.haslayer(UDP):
                display_msg += f"[UDP]\n  Src Port: {packet[UDP].sport}\n  Dst Port: {packet[UDP].dport}\n"
            elif packet.haslayer(ICMP):
                display_msg += f"[ICMP]\n  Type: {packet[ICMP].type}\n  Code: {packet[ICMP].code}\n"
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:50]  # Display first 50 bytes
            display_msg += f"[Payload]\n  {payload}\n"
        packet_size = len(packet)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        display_msg += f"[Additional Info]\n  Size: {packet_size} bytes\n  Timestamp: {timestamp}\n"
        display_msg += "=" * 50 + "\n"

        self.packet_queue.put(display_msg)
        self.packet_count += 1

    def update_gui(self):
        """Update the GUI periodically from the queue."""
        try:
            while not self.packet_queue.empty():
                display_msg = self.packet_queue.get_nowait()
                self.packet_display.insert(tk.END, display_msg)
                self.packet_display.yview(tk.END)
            self.update_packet_count()
        except Exception as e:
            print(f"Error updating GUI: {e}", file=sys.stderr)
        finally:
            if not self.stop_sniffing_flag.is_set():
                self.root.after(100, self.update_gui)

    def update_packet_count(self):
        """Update the packet count label."""
        self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")

    def on_closing(self):
        """Handle the GUI window close event."""
        print("Closing application...")
        self.stop_sniffing()
        self.root.destroy()
def run_gui():
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
if __name__ == "__main__":
    run_gui()

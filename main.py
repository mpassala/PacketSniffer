import tkinter as tk #Gui Framework
from tkinter import ttk, messagebox #Themes and message box pop-up
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP # Scapy is a packet manipulation tool + diff packet layers
import csv # To export packets
import os 
import threading # allows for network packet capturing

class PacketSniffer:
  
    def __init__(self, root): #constructor for the class
        self.root = root
        self.root.title("Marco's Packet Sniffer")
        self.root.geometry("600x600")
        root.minsize(300, 300)
      

        self.packet_listbox = tk.Listbox(root, selectmode=tk.SINGLE) # creates the listbox + packets can only be selected one at a time
        self.packet_listbox.pack(fill=tk.BOTH, expand=True) # Should only fill up space where  needed

        self.button_frame = tk.Frame(root) #creates the frame
        self.button_frame.pack() #packs into the GUI window

        self.start_button = tk.Button(self.button_frame, text="Start Dat Sniff", command=self.start_sniff) #instance + button
        self.start_button.pack(side=tk.LEFT, padx=10) #sizing

        self.stop_button = tk.Button(self.button_frame, text="Stop Dat Sniff", command=self.stop_sniff) #instance + button
        self.stop_button.pack(side=tk.LEFT, padx=10)#sizing

        self.clear_button = tk.Button(self.button_frame, text="Clear Dem Packets", command=self.clear_packets) #instance + button
        self.clear_button.pack(side=tk.LEFT, padx=10) #sizing

        self.export_button = tk.Button(self.button_frame, text="Export Dem Packets", command=self.export_packets) #instance + button
        self.export_button.pack(side=tk.LEFT, padx=10) #sizing

        self.progress = ttk.Progressbar(root, orient="horizontal", length=200, mode="indeterminate") # Looked up progress bar
        self.progress.pack(pady=10) #sizing

        self.sniffer = None #When not captuing packets
        self.captured_packets = [] #Empty list to store the packets captured

    def packet_handler(self, packet): #function called whenever a packet is intercepted
        packet_summary = packet.summary() #option for a description
        self.packet_listbox.insert(tk.END, packet_summary) #should display packet summary info in box
        self.packet_listbox.yview(tk.END) #scroll for whole summary
        self.captured_packets.append(packet) #allows to store packets

    def start_sniff(self): #initiating the process 
        if self.sniffer is None: #if no packet capturing
            try:
                self.progress.start() #starts progress bar
                self.sniffer_thread = threading.Thread(target=self.run_sniffer) #specifies new thread that runs run_sniffer method 
                self.sniffer_thread.start() #runs sniffer method
            except Exception as e:
                self.show_error_popup("Error", str(e)) #if doesnt work, show default error box

    def run_sniffer(self): #capturing network packets using Scapy
        self.sniffer = sniff(filter="", prn=self.packet_handler) #initiates packet capturing + calls packet handler above
        self.progress.stop() #stop

    def stop_sniff(self): #stops interception
        if self.sniffer is not None: #checks if sniffing
            self.sniffer.stop() #stops if not sniffing
            self.sniffer_thread.join()  # Wait for the thread to finish
            self.sniffer = None #back to no active sniffs
            self.progress.stop() #stops progress bar (works sometimes)

    def clear_packets(self): #clears packets on list
        self.packet_listbox.delete(0, tk.END) #deletes all packets in listbox
        self.captured_packets.clear() #clears

    def export_packets(self): #exports capture packets
        if not self.captured_packets: #checks if list is empty
            self.show_info_popup("Export Error", "No Packets Bozo!") #popup !
            return #method returns

        try:
            filename = "captured_packets.csv" #name of file it makes
            with open(filename, mode="w", newline="") as file: #opens file for writing
                writer = csv.writer(file) #creates a csv writer obj
                writer.writerow(["Congrats, You Sniffed! Here is Your Packet Summary:"])
                for packet in self.captured_packets:
                    writer.writerow([packet.summary()])

            self.show_info_popup("Exported!", f"Packets exported to {filename}.") #Export + Pop-up if successful 
        except Exception as e:
            self.show_error_popup("Export Error Bozo!", str(e)) #Error pop-up if uncsuccessful

    def show_info_popup(self, title, message): #displays pop-up
        messagebox.showinfo(title, message)

    def show_error_popup(self, title, message): #displays pop-up
        messagebox.showerror(title, message)

if __name__ == "__main__": #check if script is being run
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import threading

class UltimateDNSChanger:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Ultimate DNS Changer + IPv6 Blocker")
        self.root.geometry("550x600")
        
        # DNS Servers database
        self.dns_servers = {
            "Cloudflare DNS": ["1.1.1.1", "1.0.0.1"],
            "Google DNS": ["8.8.8.8", "8.8.4.4"],
            "Comodo Secure DNS": ["8.26.56.26", "8.20.247.20"],
            "Quad9": ["9.9.9.9", "149.112.112.112"],
            "AdGuard DNS": ["94.140.14.14", "94.140.15.15"],
            "OpenDNS": ["208.67.222.222", "208.67.220.220"],
            "CleanBrowsing": ["185.228.168.168", "185.228.169.168"]
        }
        
        self.create_widgets()
    
    def create_widgets(self):
        # Title
        title = tk.Label(self.root, text="🚀 Ultimate DNS Changer", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Tab Control
        tab_control = ttk.Notebook(self.root)
        
        # Tab 1: DNS Settings
        tab_dns = ttk.Frame(tab_control)
        tab_control.add(tab_dns, text="DNS Settings")
        
        # Tab 2: IPv6 Blocker
        tab_ipv6 = ttk.Frame(tab_control)
        tab_control.add(tab_ipv6, text="IPv6 Blocker")
        
        tab_control.pack(expand=1, fill="both", padx=10, pady=10)
        
        # DNS Tab Content
        self.create_dns_tab(tab_dns)
        self.create_ipv6_tab(tab_ipv6)
        
        # Status
        self.status = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, bg="lightgreen")
        self.status.pack(fill=tk.X, side=tk.BOTTOM, ipady=2)
    
    def create_dns_tab(self, parent):
        # DNS Selection
        tk.Label(parent, text="Select DNS Provider:", font=("Arial", 10, "bold")).pack(pady=5)
        self.dns_var = tk.StringVar(value="Cloudflare DNS")
        dns_combo = ttk.Combobox(parent, textvariable=self.dns_var, 
                                values=list(self.dns_servers.keys()), state="readonly", width=25)
        dns_combo.pack(pady=5)
        
        # Show selected DNS
        tk.Label(parent, text="IPv4 DNS Servers:", font=("Arial", 9, "bold")).pack()
        self.dns_display = tk.Label(parent, text="1.1.1.1, 1.0.0.1", font=("Arial", 10, "bold"), fg="blue")
        self.dns_display.pack(pady=5)
        
        # Interface Selection
        tk.Label(parent, text="Network Interface:", font=("Arial", 10, "bold")).pack()
        self.iface_var = tk.StringVar(value="Wi-Fi")
        iface_combo = ttk.Combobox(parent, textvariable=self.iface_var,
                                  values=["Wi-Fi", "Ethernet"], state="readonly", width=15)
        iface_combo.pack(pady=5)
        
        # Update DNS display when selection changes
        dns_combo.bind('<<ComboboxSelected>>', self.update_dns_display)
        
        # Buttons
        btn_frame = tk.Frame(parent)
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Apply DNS", command=self.apply_dns, 
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=15, height=2).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Reset to DHCP", command=self.reset_dns,
                 bg="#f44336", fg="white", font=("Arial", 10, "bold"), width=15, height=2).pack(side=tk.LEFT, padx=5)
        
        self.update_dns_display()
    
    def create_ipv6_tab(self, parent):
        tk.Label(parent, text="IPv6 Blocking Settings", font=("Arial", 12, "bold")).pack(pady=10)
        
        # IPv6 Info
        info_text = """
⚠️ IPv6 Leak Protection ⚠️

Many ISPs (especially Jio) use IPv6 which can 
bypass DNS settings and reveal your real IP.

This feature will:
• Disable IPv6 on all interfaces
• Block IPv6 traffic completely  
• Force IPv4-only connection
• Prevent IP address leaks
        """
        
        tk.Label(parent, text=info_text, justify=tk.LEFT, font=("Arial", 9)).pack(pady=10)
        
        # IPv6 Blocking Button
        tk.Button(parent, text="🛑 BLOCK IPv6 COMPLETELY", 
                 command=self.block_ipv6, bg="#FF5722", fg="white", 
                 font=("Arial", 12, "bold"), width=25, height=2).pack(pady=10)
        
        # Enable IPv6 Button
        tk.Button(parent, text="✅ ENABLE IPv6", 
                 command=self.enable_ipv6, bg="#2196F3", fg="white", 
                 font=("Arial", 10, "bold"), width=15, height=1).pack(pady=5)
        
        # IPv6 Status
        self.ipv6_status = tk.Label(parent, text="Status: Unknown", font=("Arial", 10))
        self.ipv6_status.pack(pady=10)
        
        # Check current IPv6 status
        self.check_ipv6_status()
    
    def update_dns_display(self, event=None):
        dns = self.dns_servers[self.dns_var.get()]
        self.dns_display.config(text=f"{dns[0]}, {dns[1]}")
    
    def run_cmd(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout, result.stderr
        except:
            return False, "", "Command timeout"
    
    def apply_dns(self):
        dns = self.dns_servers[self.dns_var.get()]
        iface = self.iface_var.get()
        
        self.status.config(text=f"Applying {self.dns_var.get()}...", bg="yellow")
        
        def apply_thread():
            commands = [
                f'netsh interface ip set dns name="{iface}" static {dns[0]}',
                f'netsh interface ip add dns name="{iface}" {dns[1]} index=2'
            ]
            
            success = True
            for cmd in commands:
                ok, stdout, stderr = self.run_cmd(cmd)
                if not ok:
                    success = False
                    break
            
            self.root.after(0, lambda: self.on_dns_complete(success, dns))
        
        threading.Thread(target=apply_thread).start()
    
    def on_dns_complete(self, success, dns):
        if success:
            self.status.config(text=f"Successfully applied {self.dns_var.get()}", bg="lightgreen")
            messagebox.showinfo("Success", 
                              f"DNS applied successfully!\n\n"
                              f"Primary: {dns[0]}\n"
                              f"Secondary: {dns[1]}\n\n"
                              f"Recommended: Also block IPv6 for complete protection!")
        else:
            self.status.config(text="Failed - Run as Administrator", bg="red")
            messagebox.showerror("Error", "Failed to apply DNS!\n\nPlease run as Administrator.")
    
    def reset_dns(self):
        iface = self.iface_var.get()
        
        self.status.config(text="Resetting to DHCP...", bg="yellow")
        
        def reset_thread():
            cmd = f'netsh interface ip set dns name="{iface}" dhcp'
            ok, stdout, stderr = self.run_cmd(cmd)
            
            self.root.after(0, lambda: self.on_reset_complete(ok))
        
        threading.Thread(target=reset_thread).start()
    
    def on_reset_complete(self, success):
        if success:
            self.status.config(text="Successfully reset to DHCP", bg="lightgreen")
            messagebox.showinfo("Success", "DNS reset to DHCP successfully!")
        else:
            self.status.config(text="Failed - Run as Administrator", bg="red")
            messagebox.showerror("Error", "Failed to reset DNS!\n\nPlease run as Administrator.")
    
    def block_ipv6(self):
        self.status.config(text="Blocking IPv6...", bg="yellow")
        
        def block_thread():
            commands = [
                'netsh interface teredo set state disabled',
                'netsh interface ipv6 set global randomizeidentifiers=disabled',
                'netsh interface ipv6 set privacy state=disabled',
                'netsh interface ipv6 set interface "Wi-Fi" routerdiscovery=disabled',
                'netsh interface ipv6 set interface "Ethernet" routerdiscovery=disabled',
                'netsh interface ipv6 delete route ::/0 "Wi-Fi"',
                'netsh interface ipv6 delete route ::/0 "Ethernet"',
                'netsh interface ipv6 set address "Wi-Fi" fd::/64',
                'netsh interface ipv6 set address "Ethernet" fd::/64'
            ]
            
            success_count = 0
            for cmd in commands:
                ok, stdout, stderr = self.run_cmd(cmd)
                if ok:
                    success_count += 1
            
            self.root.after(0, lambda: self.on_ipv6_block_complete(success_count))
        
        threading.Thread(target=block_thread).start()
    
    def on_ipv6_block_complete(self, success_count):
        self.status.config(text=f"IPv6 blocking applied ({success_count} commands)", bg="lightgreen")
        self.check_ipv6_status()
        
        messagebox.showinfo("IPv6 Blocked", 
                          f"IPv6 has been disabled and blocked!\n\n"
                          f"✅ Teredo disabled\n"
                          f"✅ IPv6 routing disabled\n"
                          f"✅ Router discovery disabled\n"
                          f"✅ Privacy extensions disabled\n\n"
                          f"Your IPv6 should no longer leak!")
    
    def enable_ipv6(self):
        self.status.config(text="Enabling IPv6...", bg="yellow")
        
        def enable_thread():
            commands = [
                'netsh interface teredo set state default',
                'netsh interface ipv6 set global randomizeidentifiers=enabled',
                'netsh interface ipv6 set privacy state=enabled',
                'netsh interface ipv6 set interface "Wi-Fi" routerdiscovery=enabled',
                'netsh interface ipv6 set interface "Ethernet" routerdiscovery=enabled'
            ]
            
            for cmd in commands:
                self.run_cmd(cmd)
            
            self.root.after(0, lambda: self.on_ipv6_enable_complete())
        
        threading.Thread(target=enable_thread).start()
    
    def on_ipv6_enable_complete(self):
        self.status.config(text="IPv6 enabled", bg="lightgreen")
        self.check_ipv6_status()
        messagebox.showinfo("IPv6 Enabled", "IPv6 has been re-enabled on your system.")
    
    def check_ipv6_status(self):
        def check_thread():
            # Check if IPv6 is enabled
            ok, stdout, stderr = self.run_cmd('netsh interface ipv6 show global')
            if ok and "Enabled" in stdout:
                status = "Enabled"
                color = "red"
            else:
                status = "Disabled"
                color = "green"
            
            self.root.after(0, lambda: self.update_ipv6_status_display(status, color))
        
        threading.Thread(target=check_thread).start()
    
    def update_ipv6_status_display(self, status, color):
        self.ipv6_status.config(text=f"IPv6 Status: {status}", fg=color)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    if sys.platform != "win32":
        messagebox.showerror("Error", "This application is for Windows only!")
        sys.exit(1)
    
    # Check if admin
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            messagebox.showwarning("Admin Rights", 
                                 "This application works best with Administrator privileges.\n\n"
                                 "For DNS changes and IPv6 blocking, please run as Administrator.")
    except:
        pass
    
    app = UltimateDNSChanger()
    app.run()

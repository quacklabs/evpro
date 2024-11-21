import sys
import os
import time
import re
import pyfiglet
from tkinter import Tk, messagebox, filedialog
from collections import defaultdict
from disposable_email_domains import blocklist
import itertools
import dns.resolver
import requests
import socks
import smtplib
import socket
from datetime import datetime
import pytz
# from dateutil import tz
import tzlocal as tzl;
import ssl
import sys
import time
import shutil
import threading

class Spinner:
    def __init__(self, text):
        self.spinner = ['-', '\\', '|', '/']
        self.text = text
        self.idx = 0
        self.running = True
        self.thread = threading.Thread(target=self.animate)

    def start(self):
        self.thread.start()

    def stop(self):
        self.running = False
        self.thread.join()

    def animate(self):
        terminal_width = shutil.get_terminal_size().columns
        spinner_position = terminal_width - 5

        while self.running:
            output = f'{self.text:<{spinner_position}}{self.spinner[self.idx]}'
            sys.stdout.write(f'\r{output}\n')
            sys.stdout.flush()
            
            # Move to the next spinner character
            self.idx = (self.idx + 1) % len(self.spinner)
            
            # Simulate some processing
            time.sleep(1)  # Adjust the speed of the spinner

class Proxy:

    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol

    def __repr__(self):
        return f"Proxy(host={self.host}, port={self.port}, protocol={self.protocol})"

class MX_Server:

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __repr__(self):
        return f"Proxy(host={self.host}, port={self.port})"

class EmailMessage:

    def __init__(self, sender_address, email_subject, email_content, recipient):
        self.sender_address = sender_address
        self.email_subject = email_subject
        self.email_content = email_content
        self.recipient = recipient

    def __repr__(self):
        return f"EmailMessage(sender_address={self.sender_address}, subject={self.email_subject}, content={email_content}, recipient={recipient})"

def check_system_time():
    try:
        # Get the system timezone
        local_tz = str(tzl.get_localzone()).replace(" ", "_")
        time_server_url = f"https://worldtimeapi.org/api/timezone/{local_tz}"

        response = requests.get(time_server_url)
        response.raise_for_status()
        server_time = datetime.fromisoformat(response.json()['utc_datetime'].replace("Z", "+00:00"))
        system_time = datetime.now(pytz.utc)

        

        time_difference = abs((server_time - system_time).total_seconds())
        if time_difference > 60 or time_difference < -60:
            show_error_dialog("Your system time is not in sync. Please update your date and time settings.")
            return False

        # Replace '2024-10-08' with your desired cutoff date
        # 
        cutoff_date = datetime.fromisoformat("2024-10-10T10:42:52.168310+00:00")
        if system_time > cutoff_date:
            show_error_dialog("This product is expired, please purchase a live copy")
            return False

        return True

    except requests.exceptions.RequestException as e:
        show_error_dialog(f"Error fetching time from server: {e}")
        sys.exit(1)

def show_error_dialog(message):
    root = Tk()
    root.withdraw()
    messagebox.showerror("Error", message)
    root.destroy()


def print_slowly(text, delay=0.05):
    """Print text slowly like a typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()  # Move to the next line

def show_intro():
    """Display software attributions and machine animation."""
    
    # Print ASCII title with pyfiglet
    title = pyfiglet.figlet_format("Email Sender Pro")
    print(title)
    time.sleep(1)

    # ASCII art with attribution
    machine = r"""
      ┌───────────────┐     ┌──────────────┐     ┌───────────────-----┐
      │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
      │. Email List . │  -> │  [Processing]│  -> │  . Email Sent    . │
      │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
      └───────────────┘     └──────────────┘     └───────────────-----┘

                Email Sender Pro v1.0 - Author: Prof 3vil
    """
    print(machine)
    time.sleep(2)

def select_emails_file():
    root = Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Select Email List",
        filetypes=[("Text Files", "*.txt")]
    )

    return file_path

def select_message_file():
    root = Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Select Message File",
        filetypes=[("Text Files", "*.txt"), ("HTML Files", "*.html")]
    )

    return file_path

def read_file(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            yield line.strip()

# Function to check if a domain contains a banned TLD
def is_banned_tld(domain):
    banned_tlds = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", "finance", ".us", ".gov"]
    return any(domain.endswith(tld) for tld in banned_tlds)

def filter_spam(text):
    spam_words = ["free", "win", "cash", "offer", "prize", "winner", "lottery", "urgent", "info", "contact", "security", "sales", "abuse", "complaints"]
    for word in spam_words:
        if word in text.lower():  # Convert email to lowercase to ensure case-insensitivity
            return False
    return True

def group_by_domain(emails):
    grouped_emails = defaultdict(list)
    for email in emails:
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) and filter_spam(email):
            domain = email.split('@')[1].strip().lower()
            if is_banned_tld(domain):
                print("Spam domain and emails detected, discarding....")
            else:
                grouped_emails[domain].append(email)

    valid_email_groups = {}

    for domain, domain_emails in grouped_emails.items():
        
        if domain in blocklist:
            print(f"Domain {domain} is blacklisted. Discarding emails.")
        else:
            valid_email_groups[domain] = domain_emails
    
    return valid_email_groups

def chunk_list(emails, batch_size):

    it = iter(emails)
    for first in it:
        yield list(itertools.chain([first], itertools.islice(it, batch_size - 1)))

    # it = iter(emails)
    # return iter(lambda: tuple(itertools.islice(it, 20)), ())

def get_mx_server(domain):
    try:
        if domain == 'outlook.com':
            return 'smtp-mail.outlook.com'
        else:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_record = sorted(mx_records, key=lambda r: r.preference)[0]
            return str(mx_record.exchange)
    except Exception as e:
        print(f"Failed to resolve MX for {domain}: {e}")
        return None

def check_smtp_port(mx_server, port, proxy):
    
    try:
        match proxy.protocol:
            case 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
            case 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
            case 'http':
                socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)

        
        # spinner = Spinner(f"Connecting via Proxy ({proxy.protocol}): {proxy.host}:{proxy.port}")
        # spinner.start()

        with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((mx_server, port))
            # connect_request = f"CONNECT {mx_server}:{port} HTTP/1.1\r\nHost: {mx_server}:{port}\r\n\r\n"
            # s.sendall(connect_request.encode())
            if proxy.protocol == 'http':
                connect_request = f"CONNECT {mx_server}:{port} HTTP/1.1\r\nHost: {mx_server}:{port}\r\n\r\n"
                s.send(connect_request.encode('utf-8'))

            response = s.recv(4096).decode('utf-8')
            # spinner.stop()

            if "200" in response:
                return True
            else:
                return False
        # spiner.stop()
            
    except Exception as e:
        # print(f'Mail Exchange Connection failed {e}')
        return False
    
def find_valid_smtp_port(mx_server, proxies):

    print(f"Checking SMTP ports for {mx_server}:")
    for port in [25, 587, 465, 2525]:
        
        # spinner = Spinner(f"Waiting for connection: {mx_server}:{port}...")
        # spinner.start()
        print("Waiting for connection on port: {port}")

        for idx, proxy in enumerate(proxies, start=1):
            print(f"Connecting via proxy ({proxy.protocol}): {proxy.host}:{proxy.port} ... ({idx}/{len(proxies)})")
            # spinner.start()
            try:
                if check_smtp_port(mx_server, port, proxy):
                    sys.stdout.flush()
                    return proxy, port

            except Exception as e:
                # spinner.stop()
                continue
            # spinner.stop()
        # spinner.stop()

    return None  # Return None if no valid port is found

def fetch_proxy():

    api_url = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=us&protocol=http,socks4,socks5&proxy_format=ipport&format=json&timeout=10000"

    try:
        headers = {
            "Content-type" : "application/json",
            "Accept" : "application/json"
        }
        response = requests.get(api_url, headers)
        print(f'Proxies fetched: {len(response.json()['proxies'])}')
        proxies = response.json()['proxies']

        return [Proxy(proxy['ip'], proxy['port'], proxy['protocol']) for proxy in proxies]
    except:
        print('Failed to get proxies')
        return

def save_valid_email(email, save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.expanduser("~"), "Desktop")

    file_path = os.path.join(save_dir, "successful_emails.txt")

    with open(file_path, 'a') as file:
        file.write(email + '\n')
        return

def save_failed_email(email, save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.expanduser("~"), "Desktop")

    file_path = os.path.join(save_dir, "failed_emails.txt")

    with open(file_path, 'a') as file:
        file.write(email + '\n')
        return
            

def detect_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read(1024).lower()
            if '<html>' in content or '<body>' in content:
                return "HTML"
            else:
                return "Text"
    except Exception as e:
        print("Error parsing message content: {e}")
        return None

def send_mail(message, mx, proxy, mime_type="HTML"):
    try:
        match proxy.protocol:
            case 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
            case 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
            case 'http':
                socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)

        with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(20)
            s.connect((mx_server.host, mx_server.port))

            s.send(f"EHLO {mx_server.host}\r\n".encode())

            response = s.recv(1024).decode()
            if "550" in response or "5.0.0" in response:
                print("Server Rejected")
                return False

            s.send(b"STARTTLS\r\n".encode())
            response = s.recv(1024).decode()
            if "550" in response or "5.0.0" in response:
                print("Server Rejected SSL")
                return False

            s = ssl.wrap_socket(s)
            headers = (f"From: {message.sender_address}\r\n To: {message.recipient}\r\n Subject: {message.email_subject}\r\n MIME-Version: 1.0\r\n Content-Type: text/html; charset=utf-8\r\n\r\n")
            message = headers + message.email_content + "\r\n.\r\n"
            # Example SMTP commands
            commands = [
                f"EHLO {proxy.host}\r\n",
                f"MAIL FROM:<{message.sender_address}>\r\n",  # Replace with a valid email
                f"RCPT TO:<{message.recipient}>\r\n",  # Replace with a valid recipient
                f"DATA\r\n",
                f"{message}",
                "QUIT\r\n"
            ]

            for command in commands:
                print(f"Sending: {command.strip()}")
                s.send(command.encode())
                response = s.recv(1024).decode()

                # Return false if any command fails before RCPT TO
                if "550" in response or "5.0.0" in response:  # You can adjust the error codes you want to check
                    print(f'{response}')
                    return False  # Indicates a failure
            s.close()
            return True

    except Exception as e:

        return False

    return False


def detonate(email_file_path, message_file_path, sender_address, subject):
    emails = read_file(email_file_path)
    domain_groups = group_by_domain(emails)
    content_type = detect_content(message_file_path)

    batch_number = 1
    for domain, email_list in domain_groups.items():
        print(f"Validating emails for domain: {domain}")

        mx_server = get_mx_server(domain)
        # proxies = fetch_proxy()

        if mx_server and content_type:

            for email_batch in  chunk_list(email_list, 20):
                proxy_list = fetch_proxy()

                result = find_valid_smtp_port(mx_server, proxy_list)

                if result:
                    proxy = result[0]
                    smtp_port = result[1]
                    mx = MX_Server(mx_server, smtp_port)

                    for email in email_batch:
                        total_emails = len(email_batch)
                        sent_emails = 0
                        content = read_file(message_file_path)
                        message = EmailMessage(sender_address, subject, content, email)

                        spinner = Spinner(f"Sending email to: {email}...")
                        spinner.start()


                        if send_mail(message, mx, proxy, content_type):
                            sent_emails += 1
                            save_valid_email(email)
                            print(f"Email sent successfully: {email}")
                        else:
                            save_failed_email(email)
                            print(f"Failed to send email to {email}")

                        spinner.stop()

                    sys.stdout.flush()
                    batch_number += 1   
                    print(f"Succesfully sent batch {batch_number}", end="\n")
                    print(f"Success: {sent_emails}/{total_emails}", end="\n")

        else:
            print('Unable to find valid mx server for domain, possibly invalid')

    messagebox.showerror("Sending complete", "Email processed successfully, you can close the window now")
    sys.exit(1)

def valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None


def get_sender_address():
    while True:
        email = input("Enter Sender Address: ")
        if valid_email(email):
            return email

def get_subject():
    while True:
        subject = input("Enter email subject: ")
        if subject is not None:
            return subject

if __name__ == "__main__":
    if not check_system_time():
        sys.exit(1)
    else:
        show_intro()
        print("Please upload you email list")
        time.sleep(1)
        email_file_path = select_emails_file()
        print("Loading emails...")
        time.sleep(1)
        print("Please upload message file")
        message_file_path = select_message_file()
    
        if email_file_path and message_file_path:
            sender_address = get_sender_address()
            if sender_address:
                email_subject = get_subject()

                if email_subject:
                    detonate(email_file_path, message_file_path, sender_address, email_subject)
        else:
            print("No files selected.")
            messagebox.showerror("No File Selected", "You must select a file to proceed.")
            sys.exit(1)

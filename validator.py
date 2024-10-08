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
    title = pyfiglet.figlet_format("Email Validator")
    print(title)
    time.sleep(1)

    # ASCII art with attribution
    machine = r"""
      ┌───────────────┐     ┌──────────────┐     ┌───────────────-----┐
      │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
      │. Email List . │  -> │  [Processing]│  -> │  . Valid Emails  . │
      │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
      └───────────────┘     └──────────────┘     └───────────────-----┘

                Email Validator v1.0 - Author: Trakand R&D
              Contributors: OpenAI & Python Community | 2024
    """
    print(machine)
    time.sleep(2)

def select_file():
    root = Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Select Email List",
        filetypes=[("Text Files", "*.txt")]
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


def filter_spam(email):
    spam_words = ["free", "win", "cash", "offer", "prize", "winner", "lottery", "urgent", "info", "contact", "security", "sales", "abuse", "complaints"]
    for word in spam_words:
        if word in email.lower():  # Convert email to lowercase to ensure case-insensitivity
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

def save(batch, batch_number, save_dir=None):

    if save_dir is None:
        save_dir = os.path.join(os.path.expanduser("~"), "Desktop")

    file_path = os.path.join(save_dir, "validated_emails.txt")

    with open(file_path, 'a') as file:
        for email in batch:
            file.write(email + '\n')


def check_smtp_port(mx_server, port, proxy):
    
    try:
        match proxy.protocol:
            case 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
            case 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
            case 'http':
                socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)

        # socket.socket = socks.socksocket

        with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(20)
            s.connect((mx_server, port))
            # connect_request = f"CONNECT {mx_server}:{port} HTTP/1.1\r\nHost: {mx_server}:{port}\r\n\r\n"
            # s.sendall(connect_request.encode())
            connect_request = f"CONNECT {mx_server}:{port} HTTP/1.1\r\nHost: {mx_server}:{port}\r\n\r\n"
            s.send(connect_request.encode('utf-8'))

            response = s.recv(4096).decode('utf-8')
            
            if "200" in response:
                return True
            else:
                return False
            
    except Exception as e:
        # print(f'Mail Exchange Connection failed {e}')
        return False
    

def find_valid_smtp_port(mx_server, proxies):

    print(f"Checking SMTP ports for {mx_server}:")
    for port in [25, 587, 465, 2525]:

        for idx, proxy in enumerate(proxies, start=1):
            print(f"Connecting via proxy ({proxy.protocol}): {proxy.host}:{proxy.port} ... ({idx}/{len(proxies)})", end="\r\n")
            try:
                if check_smtp_port(mx_server, port, proxy):
                    return proxy, port
            except Exception as e:
                print(f"Failed to connect to port {port} with proxy {proxy['host']}:{proxy['port']} - {e}")
                continue

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

    return 

def validate_email_rcpt(email, mx_server, proxy):

    try:
        match proxy.protocol:
            case 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
            case 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
            case 'http':
                socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)

        # socket.socket = 

        with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(20)
            s.connect((mx_server.host, mx_server.port))

            # Example SMTP commands
            commands = [
                f"EHLO {proxy.host}\r\n",
                f"MAIL FROM:<{email}>\r\n",  # Replace with a valid email
                f"RCPT TO:<{email}>\r\n",  # Replace with a valid recipient
                "QUIT\r\n"
            ]

            for command in commands:
                print(f"Sending: {command.strip()}")
                s.sendall(command.encode())
                response = s.recv(4096).decode()
                print(f"Server response: {response}")

                # Return false if any command fails before RCPT TO
                if "550" in response or "5.0.0" in response:  # You can adjust the error codes you want to check
                    return False  # Indicates a failure

            return True
            
    except Exception as e:
        # print(f'SMTP Connection failed {e}')
        return False

def process_file(file_path):
    emails = read_file(file_path)
    domain_groups = group_by_domain(emails)

    batch_number = 1
    for domain, email_list in domain_groups.items():
        print(f"Validating emails for domain: {domain}")

        mx_server = get_mx_server(domain)
        proxies = fetch_proxy()

        if mx_server and proxies:

            valid_emails = []
            validated_sample = 0

            result = find_valid_smtp_port(mx_server, proxies)

            if result:
                print(f"SMTP Port found: {result[1]}")
                # return True
                proxy = result[0]
                smtp_port = result[1]
                mx = MX_Server(mx_server, smtp_port)

                for email_batch in  chunk_list(email_list, 20):

                    for email in email_batch:
                        if validated_sample < 4:  # Only validate a small sample
                            if validate_email_rcpt(email, mx, proxy):
                                valid_emails.append(email)
                                validated_sample += 1
                        else:
                            # Assume remaining emails are valid after sample size is validated
                            valid_emails.append(email)

                    # Save the valid emails for this batch
                    if valid_emails:
                        save(valid_emails, batch_number)
                        print(f"Batch {batch_number} saved with {len(valid_emails)} valid emails.")
                        batch_number += 1
            else:
                print(f"No valid emails found for domain {domain}.")
        else:
            print('Unable to find valid mx server for domain, possibly invalid')


    messagebox.showerror("Validation Completed", "Email processed successfully, you can close the window now")
    sys.exit(1)

if __name__ == "__main__":
    if not check_system_time():
        sys.exit(1)
    else:
        show_intro()
        print("Please upload you email list")
        time.sleep(1)
        file_path = select_file()
    
        if file_path:
            process_file(file_path)
        else:
            print("No file selected.")
            messagebox.showerror("No File Selected", "You must select a file to proceed.")
            sys.exit(1)

# import requests
# import tkinter as tk
# from tkinter import filedialog
# import os
# import random
# import smtplib
# import itertools
# import socks
# import socket

# counter = 0

# # Function to perform login and retrieve token
# def login(username, password):
#     url = 'https://example.com/login'  # Replace with actual API endpoint
#     data = {
#         'username': username,
#         'password': password
#     }
#     response = requests.post(url, json=data)
    
#     if response.status_code == 200 and response.json().get('status') == 'success':
#         return response.json().get('token')
#     return None

# # Function to fetch a proxy using the token
# def fetch_proxy():
#     url = 'https://gimmeproxy.com/api/getProxy'  # Replace with actual API endpoint for single proxy
#     headers = {'Content-type': 'application/json', 'Accept' : 'application/json'}
#     response = requests.get(url, headers=headers)
    
#     if response.status_code == 200:
#         return response.json()  # Assuming the response contains a 'proxy' field
#     return None

# # Function to open file dialog and read emails
# def open_file_and_read_emails():
#     root = tk.Tk()
#     root.withdraw()  # Hide the main tkinter window

#     file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])

#     if file_path:
#         with open(file_path, 'r') as file:
#             emails = [email.strip() for email in file.readlines() if email.strip()]
#         return emails
#     return []

# # Function to chunk a list into batches of a given size
# def chunk_list(data, chunk_size):
#     it = iter(data)
#     return iter(lambda: tuple(itertools.islice(it, chunk_size)), ())



# # Function to extract domain from email
# def get_domain_from_email(email):
#     return email.split('@')[-1]


# def get_mx_server(domain):
#     try:
#         if domain == 'outlook.com':
#             return 'smtp-mail.outlook.com'
#         else:
#             mx_records = dns.resolver.resolve(domain, 'MX')
#             mx_record = sorted(mx_records, key=lambda r: r.preference)[0]
#             return str(mx_record.exchange)
#     except Exception as e:
#         print(f"Failed to resolve MX for {domain}: {e}")
#         return None

# def check_smtp_port(mx_server, port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.settimeout(5)  # Set timeout for the connection
#         try:
#             s.connect((mx_server, port))
#             print(f"Port {port} is open on {mx_server}.")
#             return True
#         except (socket.error, socket.timeout):
#             print(f"Port {port} is closed on {mx_server}.")
#             return False



# def write_valid_email_to_file(email):
#     # Get the path to the user's desktop
#     desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
#     file_path = os.path.join(desktop_path, "validated_emails.txt")

#     # Open the file in append mode; create it if it doesn't exist
#     with open(file_path, "a") as file:
#         file.write(email + "\n")  # Write the email followed by a newline

# # Function to send RCPT command to email server using a proxy and MX server
# def send_rcpt(proxy, emails, use_proxy=True):
#     try:
#         # Extract proxy host and port
#         proxy_host = proxy.get('ip')
#         proxy_port = proxy.get('port')
#         protocol = proxy.get('protocol')
#         socket.setdefaulttimeout(10)

#         print(f'Using: IP: {proxy_host}:{proxy_port}')
        
#         for email in emails:
#             domain = get_domain_from_email(email)
#             mx_server = get_mx_server(domain)
#             print(f'Found MX server: {mx_server}')
            

#             if mx_server:
#                 smtp_port = find_valid_smtp_port(mx_server)
                
#                 if smtp_port:

#                     if use_proxy == True:
#                         print(f'Connecting via {protocol}')
#                         # Connect to the MX server using the proxy
#                         if protocol == 'http' or protocol == 'https':
                            
#                             proxies = {
#                                 "http": f"http://{proxy_host}:{proxy_port}",
#                                 "https": f"http://{proxy_host}:{proxy_port}",
#                             }

#                             try:
                                
#                                 smtp = smtplib.SMTP(mx_server, smtp_port)
#                                 smtp.ehlo()  # Identify yourself to the server

#                             except requests.exceptions.RequestException as e:
#                                 print(f"Error: Could not connect via proxy. Details: {e}")
#                                 return
                            

#                         elif protocol == 'socks5' or protocol == 'socks4':
#                             socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
#                             socks.wrapmodule(smtplib)
#                             # socket.socket = socks.socksocket

#                             # Connect to the MX server using the SOCKS5 proxy
#                             smtp = smtplib.SMTP(mx_server, smtp_port)
#                             smtp.ehlo()
#                     else:
#                         print('Connnecting without proxy')
#                         smtp = smtplib.SMTP(mx_server, smtp_port)
#                         smtp.ehlo()  # Identify yourself to the server



#                     print(f'Sending EMAIL command for {email}')
#                     smtp.mail(email)
#                     # Send RCPT command
#                     code, message = smtp.rcpt(email)
#                     if 200 <= code < 300:
#                         print(f"RCPT command for {email} was successful: {code} {message}")
#                         write_valid_email_to_file(email)
#                     else:
#                         print(f"RCPT command for {email} failed: {code} {message}")
                    
#                     smtp.quit()
#                 else:
#                     print(f'Unable to find SMTP port for {mx_server}')
#                     return
#             else:
#                 print(f"Skipping {email}, unable to resolve MX server for domain {domain}.")
    
#     except Exception as e:
#         global counter
#         print(f"Error using proxy {proxy}: {e}")
#         counter += 1
#         if counter > 1:
#         #     counter = 0
#             return
#         else:
#             print(f'Failed to send using proxy. Trying without proxy...')
#             send_rcpt(proxy, emails, False)
#             return

# # Main function to execute the workflow
# def main():
#     print("Welcome! Please select your email list.")
    
#     emails = open_file_and_read_emails()
#     if not emails:
#         print("No emails found in the selected file.")
#         return
#     print('loading emails...')
#     batch_size = 20
#     email_batches = chunk_list(emails, batch_size)
    
#     # Step 4: For each batch, fetch a proxy and process emails
#     for batch in email_batches:
#         print(f'emails loaded!, processing batch {batch}')
#         # Request a new proxy for each batch
#         proxy = fetch_proxy()
        
#         if proxy:
#             # Send RCPT commands to the batch using the newly fetched proxy
#             send_rcpt(proxy, batch)
#         else:
#             print("Failed to fetch proxy for this batch. Skipping.")

#     print('Emails validation task completed')

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
            print(f"Connecting via proxy ({proxy.protocol}): {proxy.host}:{proxy.port} ... ({idx}/{len(proxies)})", end="\r")
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
    show_intro()
    print("Please upload you email list")
    time.sleep(2)
    file_path = select_file()
    
    if file_path:
        process_file(file_path)
    else:
        print("No file selected.")
        messagebox.showerror("No File Selected", "You must select a file to proceed.")
        sys.exit(1)

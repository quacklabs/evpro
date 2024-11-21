# import sys
# import os
# import re
# import pyfiglet
# from tkinter import Tk, messagebox, filedialog


# import requests
# import socks
# import smtplib
# import socket

# from EEPro import Engine,  print_slowly, select_file, read_file
# from license import License



# engine = Engine()
# license = License()

# def show_error_dialog(message):
#     root = Tk()
#     root.withdraw()
#     messagebox.showerror("Error", message)
#     root.destroy()

# def show_intro():
#     """Display software attributions and machine animation."""
    
#     # Print ASCII title with pyfiglet
#     title = pyfiglet.figlet_format("Email Validator")
#     print(title)

#     # ASCII art with attribution
#     machine = r"""
#       ┌───────────────┐     ┌──────────────┐     ┌───────────────-----┐
#       │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
#       │. Email List . │  -> │  [Processing]│  -> │  . Valid Emails  . │
#       │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
#       └───────────────┘     └──────────────┘     └───────────────-----┘

#                 Email Validator v1.0 - Author: Trakand R&D
#               Contributors: OpenAI & Python Community | 2024
#     """
#     print(machine)


#     # it = iter(emails)
#     # return iter(lambda: tuple(itertools.islice(it, 20)), ())



# def save(batch, batch_number, save_dir=None):

#     if save_dir is None:
#         save_dir = os.path.join(os.path.expanduser("~"), "Desktop")

#     file_path = os.path.join(save_dir, "validated_emails.txt")

#     with open(file_path, 'a') as file:
#         for email in batch:
#             file.write(email + '\n')


# def check_smtp_port(mx_server, port, proxy):
    
#     try:
#         match proxy.protocol:
#             case 'socks4':
#                 socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
#             case 'socks5':
#                 socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
#             case 'http':
#                 socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)

#         # socket.socket = socks.socksocket

#         with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(20)
#             s.connect((mx_server, port))
#             # connect_request = f"CONNECT {mx_server}:{port} HTTP/1.1\r\nHost: {mx_server}:{port}\r\n\r\n"
#             # s.sendall(connect_request.encode())
#             connect_request = f"CONNECT {mx_server}:{port} HTTP/1.1\r\nHost: {mx_server}:{port}\r\n\r\n"
#             s.send(connect_request.encode('utf-8'))

#             response = s.recv(4096).decode('utf-8')
            
#             if "200" in response:
#                 return True
#             else:
#                 return False
            
#     except Exception as e:
#         # print(f'Mail Exchange Connection failed {e}')
#         return False
    

# def find_valid_smtp_port(mx_server, proxies):

#     print(f"Checking SMTP ports for {mx_server}:")
#     for port in [25, 587, 465, 2525]:

#         for idx, proxy in enumerate(proxies, start=1):
#             print(f"Connecting via proxy ({proxy.protocol}): {proxy.host}:{proxy.port} ... ({idx}/{len(proxies)})", end="\r\n")
#             try:
#                 if check_smtp_port(mx_server, port, proxy):
#                     return proxy, port
#             except Exception as e:
#                 print(f"Failed to connect to port {port} with proxy {proxy['host']}:{proxy['port']} - {e}")
#                 continue

#     return None  # Return None if no valid port is found

# def fetch_proxy():

#     api_url = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=us&protocol=http,socks4,socks5&proxy_format=ipport&format=json&timeout=10000"

#     try:
#         headers = {
#             "Content-type" : "application/json",
#             "Accept" : "application/json"
#         }
#         response = requests.get(api_url, headers)
#         print(f'Proxies fetched: {len(response.json()['proxies'])}')
#         proxies = response.json()['proxies']

#         return [Proxy(proxy['ip'], proxy['port'], proxy['protocol']) for proxy in proxies]
#     except:
#         print('Failed to get proxies')
#         return

#     return 

# def validate_email_rcpt(email, mx_server, proxy):

#     try:
#         match proxy.protocol:
#             case 'socks4':
#                 socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
#             case 'socks5':
#                 socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
#             case 'http':
#                 socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)

#         # socket.socket = 

#         with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(20)
#             s.connect((mx_server.host, mx_server.port))

#             # Example SMTP commands
#             commands = [
#                 f"EHLO {proxy.host}\r\n",
#                 f"MAIL FROM:<{email}>\r\n",  # Replace with a valid email
#                 f"RCPT TO:<{email}>\r\n",  # Replace with a valid recipient
#                 "QUIT\r\n"
#             ]

#             for command in commands:
#                 print(f"Sending: {command.strip()}")
#                 s.sendall(command.encode())
#                 response = s.recv(4096).decode()
#                 print(f"Server response: {response}")

#                 # Return false if any command fails before RCPT TO
#                 if "550" in response or "5.0.0" in response:  # You can adjust the error codes you want to check
#                     return False  # Indicates a failure

#             return True
            
#     except Exception as e:
#         # print(f'SMTP Connection failed {e}')
#         return False

# def process_file(file_path):
#     emails = engine.read_file(file_path)
#     domain_groups = engine.group_by_domain(emails)

#     batch_number = 1
#     for domain, email_list in domain_groups.items():
#         print(f"Validating emails for domain: {domain}")

#         mx_server = get_mx_server(domain)
#         proxies = fetch_proxy()


#         if mx_server:

#             # for thread_name, result, progress_updates in engine.process(email_validation, mx_server, domain, email_list):


#             valid_emails = []
#             validated_sample = 0

#             result = find_valid_smtp_port(mx_server, proxies)

#             if result:
#                 print(f"SMTP Port found: {result[1]}")
#                 # return True
#                 proxy = result[0]
#                 smtp_port = result[1]
#                 mx = MX_Server(mx_server, smtp_port)

#                 for email_batch in  chunk_list(email_list, 20):

#                     for email in email_batch:
#                         if validated_sample < 4:  # Only validate a small sample
#                             if validate_email_rcpt(email, mx, proxy):
#                                 valid_emails.append(email)
#                                 validated_sample += 1
#                         else:
#                             # Assume remaining emails are valid after sample size is validated
#                             valid_emails.append(email)

#                     # Save the valid emails for this batch
#                     if valid_emails:
#                         save(valid_emails, batch_number)
#                         print(f"Batch {batch_number} saved with {len(valid_emails)} valid emails.")
#                         batch_number += 1
#             else:
#                 print(f"No valid emails found for domain {domain}.")
#         else:
#             print('Unable to find valid mx server for domain, possibly invalid')


#     messagebox.showerror("Validation Completed", "Email processed successfully, you can close the window now")
#     sys.exit(1)

# if __name__ == "__main__":

#     show_intro()
#     print("Please upload you email list")
#     file_path = select_file([("Text Files", "*.txt")])

#     if file_path:
#         process_file(file_path)
#     else:
#         print("No file selected.")
#         messagebox.showerror("No File Selected", "You must select a file to proceed.")
#         sys.exit(1)
    
#     # print_slowly("Checking License...")

#     # check = license.check_license()

#     # if check:
#     #     if "OK" not in check:
#     #         show_error_dialog(check)
#     #         sys.exit(1)
#     #     else:
            
#     # else:
#     #     show_error_dialog("Unable to validate")
#     #     sys.exit(1)
        

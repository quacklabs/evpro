import sys
import os
import pyfiglet
from tkinter import Tk, messagebox, filedialog
import smtplib
import socket
import ssl
import threading
from queue import Queue
from itertools import islice
import dns.resolver
from collections import defaultdict
import re

# Embedded classes (replacing servers.py)
class MX_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)

# Embedded disposable email domains blocklist (subset for self-containment)
blocklist = {
    'mailinator.com', 'guerrillamail.com', '10minutemail.com',
    'tempmail.com', 'throwawaymail.com', 'yopmail.com'
}

class License:
    def check_license(self) -> str:
        """Dummy license check."""
        return "OK"

# Initialize license
license = License()

# Cache for MX servers per domain
_mx_cache = {}
# Lock for thread-safe SMTP connections
_smtp_lock = threading.Lock()
# Store original socket for IPv4 enforcement
_original_socket = socket.socket

def show_error_dialog(message: str):
    root = Tk()
    root.withdraw()
    messagebox.showerror("Error", message)
    root.destroy()

def show_intro():
    """Display software attributions and machine animation."""
    title = pyfiglet.figlet_format("Email Validator")
    print(title)
    machine = r"""
      ┌───────────────┐     ┌──────────────┐     ┌───────────────-----┐
      │  . . . . . .  │     │   /////////  │     │  . Valid Emails  . │
      │. Email List . │  -> │  [Processing]│  -> │  . . . . . . . . . │
      │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
      └───────────────┘     └──────────────┘     └───────────────-----┘

                Email Validator v1.0 - Author: Trakand R&D
              Contributors: OpenAI & Python Community | 2024
    """
    print(machine)

def save(emails: list[str], save_dir: str = None):
    """Save validated emails to a single file on the Desktop."""
    if save_dir is None:
        save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(save_dir, "validated_emails.txt")
    with open(file_path, 'a') as f:
        for email in emails:
            f.write(email + '\n')

def chunk_list(lst: list, chunk_size: int):
    """Yield successive chunk_size-sized chunks from lst."""
    iterator = iter(lst)
    return iter(lambda: tuple(islice(iterator, chunk_size)), ())

def select_file(file_types):
    """Select a file using a GUI dialog."""
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Select file", filetypes=file_types)
    return file_path

def read_file(file_path):
    """Read lines from a file, yielding stripped strings."""
    with open(file_path, 'r') as f:
        for line in f:
            yield line.strip()

def is_banned_tld(domain):
    """Check if domain has a banned TLD."""
    banned_tlds = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", ".finance", ".gov", ".gov.ng", ".gov.us"]
    return any(domain.endswith(tld) for tld in banned_tlds)

def filter_spam(email):
    """Filter out emails with spam-related keywords."""
    spam_words = [
        "free", "win", "cash", "offer",
        "prize", "winner", "lottery",
        "urgent", "security", "abuse",
        "complaints", "webmaster", "report",
    ]
    return not any(word in email.lower() for word in spam_words)

def group_by_domain(emails):
    """Group emails by domain, filtering out spam and banned TLDs."""
    grouped_emails = defaultdict(list)
    for email in emails:
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) and filter_spam(email.split('@')[0].strip()):
            domain = email.split('@')[1].strip().lower()
            if not is_banned_tld(domain) and domain not in blocklist:
                grouped_emails[domain].append(email)
    return grouped_emails

def get_mx_servers(domain):
    """Resolve MX servers for a domain."""
    if domain in _mx_cache:
        return _mx_cache[domain]
    try:
        if domain == 'outlook.com':
            mx_servers = [MX_Server('smtp-mail.outlook.com', 25)]
        else:
            # Force IPv4 for DNS resolution
            socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: _original_socket(family, type_, proto)
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_servers = [MX_Server(str(record.exchange).rstrip('.'), 25) for record in sorted(mx_records, key=lambda r: r.preference)]
        _mx_cache[domain] = mx_servers
        return mx_servers
    except Exception as e:
        print(f"Failed to get MX servers for {domain}: {e}")
        return []
    finally:
        socket.socket = _original_socket

def validate_email_rcpt(email: str, mx_server: MX_Server, retries: int = 2) -> bool:
    """Validate an email via SMTP RCPT TO command with retry logic."""
    attempt = 0
    while attempt <= retries:
        try:
            with _smtp_lock:  # Ensure thread-safe SMTP connections
                # Force IPv4 for SMTP connection
                socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: _original_socket(family, type_, proto)
                context = ssl.create_default_context()
                with smtplib.SMTP(mx_server.host, mx_server.port, timeout=6) as server:
                    server.ehlo('localhost')
                    if mx_server.port != 465:
                        try:
                            server.starttls(context=context)
                            server.ehlo('localhost')
                        except smtplib.SMTPNotSupportedError:
                            pass  # Some servers don't support STARTTLS on port 25
                    server.mail("validator@example.com")
                    code, msg = server.rcpt(email)
                    print(f"[{email}] RCPT TO:<{email}> -> {code} {msg.decode('utf-8') if isinstance(msg, bytes) else msg}")
                    return code == 250
        except socket.timeout:
            print(f"Timeout validating {email} (attempt {attempt + 1}/{retries + 1})")
        except socket.gaierror as e:
            print(f"DNS resolution error for {mx_server.host}: {e} (attempt {attempt + 1}/{retries + 1})")
        except smtplib.SMTPRecipientsRefused:
            print(f"Recipient {email} refused by {mx_server.host}")
            return False
        except smtplib.SMTPNotSupportedError as e:
            print(f"SMTP command not supported for {email}: {e} (attempt {attempt + 1}/{retries + 1})")
        except smtplib.SMTPException as e:
            print(f"SMTP error validating {email}: {e} (attempt {attempt + 1}/{retries + 1})")
        except Exception as e:
            print(f"Unexpected error validating {email}: {e} (attempt {attempt + 1}/{retries + 1})")
        finally:
            socket.socket = _original_socket
        attempt += 1

    print(f"Failed to validate {email} after {retries + 1} attempts")
    return False

def process_batch(email_batch: list[str], mx_server: MX_Server, result_queue: Queue):
    """Process a batch of emails and store valid ones in the queue."""
    valid_emails = []
    for email in email_batch:
        if validate_email_rcpt(email, mx_server):
            valid_emails.append(email)
            print(f"Valid email: {email}")
        else:
            print(f"Invalid email: {email}")
    result_queue.put(valid_emails)

def process_domain(domain: str, email_list: list[str]):
    """Process all emails for a given domain using multithreading."""
    print(f"\nProcessing domain: {domain} ({len(email_list)} emails)")
    mx_servers = get_mx_servers(domain)
    if not mx_servers:
        print(f"No MX servers found for {domain}")
        return

    # Try each MX server until one works
    mx_server = None
    for server in mx_servers:
        test_email = email_list[0]
        if validate_email_rcpt(test_email, server):
            mx_server = server
            break
    if not mx_server:
        print(f"No working MX server found for {domain}")
        return

    print(f"Using MX server {mx_server.host}:{mx_server.port}")

    result_queue = Queue()
    threads = []
    batch_size = 20
    for email_batch in chunk_list(email_list, batch_size):
        t = threading.Thread(target=process_batch, args=(email_batch, mx_server, result_queue))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    valid_emails = []
    while not result_queue.empty():
        valid_emails.extend(result_queue.get())

    if valid_emails:
        save(valid_emails)
        print(f"Saved {len(valid_emails)} valid emails for {domain}")
    else:
        print(f"No valid emails found for {domain}")

def process_file(file_path: str):
    """Process the email list file with multithreading."""
    if license.check_license() != "OK":
        show_error_dialog("License validation failed")
        sys.exit(1)

    try:
        # Convert generator to list and remove duplicates
        emails = list(set(read_file(file_path)))
        print(f"Loaded {len(emails)} unique emails")
        domain_groups = group_by_domain(emails)
    except Exception as e:
        show_error_dialog(f"Failed to process file: {e}")
        sys.exit(1)

    threads = []
    for domain, email_list in domain_groups.items():
        t = threading.Thread(target=process_domain, args=(domain, email_list))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    messagebox.showinfo("Validation Completed", "Email validation completed. Results saved to Desktop/validated_emails.txt")
    sys.exit(0)

def main():
    """Main function to run the email validator."""
    show_intro()
    print("Please select your email list file")
    file_path = select_file([("Text Files", "*.txt")])
    
    if file_path:
        output_file = os.path.join(os.path.expanduser("~"), "Desktop", "validated_emails.txt")
        if os.path.exists(output_file):
            os.remove(output_file)
        process_file(file_path)
    else:
        show_error_dialog("No file selected")
        sys.exit(1)
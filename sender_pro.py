import sys
import os
import time
import random
import re
import pyfiglet
from tkinter import Tk, messagebox, filedialog, simpledialog
from collections import defaultdict, deque
import itertools
import dns.resolver
import smtplib
import socket
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
from datetime import datetime
from email.utils import formataddr

# Embedded disposable email domains blocklist (subset for self-containment)
blocklist = {
    'mailinator.com', 'guerrillamail.com', '10minutemail.com',
    'tempmail.com', 'throwawaymail.com', 'yopmail.com'
}

# Embedded MX server class
class MX_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)

class RateLimiter:
    def __init__(self, default_limit_per_hour=43):
        self.default_limit_per_hour = default_limit_per_hour
        self.sent_times = defaultdict(deque)
        self.limits = {}
        self.lock = threading.Lock()

    def set_limit(self, host, port, limit):
        with self.lock:
            self.limits[(host, port)] = limit
            print(f"Set rate limit for {host}:{port} to {limit} emails per hour")

    def reset(self):
        with self.lock:
            self.sent_times.clear()
            print("Rate limiter reset. All sent_times cleared.")

    def can_send(self, host, port):
        with self.lock:
            current_time = time.time()
            key = (host, port)
            limit = self.limits.get(key, self.default_limit_per_hour)
            while self.sent_times[key] and current_time - self.sent_times[key][0] > 3600:
                self.sent_times[key].popleft()
            current_count = len(self.sent_times[key])
            print(f"Rate limiter check for {host}:{port}: {current_count}/{limit} emails sent in last hour")
            if current_count >= limit:
                print(f"Rate limit reached for {host}:{port}, {current_count} emails sent")
                return False
            return True

    def record_send(self, host, port):
        with self.lock:
            key = (host, port)
            self.sent_times[key].append(time.time())
            print(f"Recorded send for {host}:{port}, new count: {len(self.sent_times[key])}")

    def time_until_next_slot(self, host, port):
        with self.lock:
            key = (host, port)
            limit = self.limits.get(key, self.default_limit_per_hour)
            current_count = len(self.sent_times[key])
            if current_count < limit:
                print(f"No wait needed for {host}:{port}, {current_count}/{limit} emails sent")
                return 0
            oldest_time = self.sent_times[key][0]
            current_time = time.time()
            wait_time = 3600 - (current_time - oldest_time)
            print(f"Waiting {wait_time:.2f} seconds for next slot for {host}:{port}")
            return wait_time

# Global variables
rate_limiter = RateLimiter(default_limit_per_hour=43)
successful_emails = set()
threads = []
lock = threading.Lock()
smtp_lock = threading.Lock()
_original_socket = socket.socket
_mx_cache = {}

def show_error_dialog(message):
    root = Tk()
    root.withdraw()
    messagebox.showerror("Error", message)
    root.destroy()

def print_slowly(text, delay=0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_intro():
    title = pyfiglet.figlet_format("Email Sender Pro")
    print(title)
    time.sleep(1)
    machine = r"""
      ┌───────────────┐     ┌──────────────┐     ┌───────────────-----┐
      │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
      │. Email List . │  -> │  [Processing]│  -> │  . Email Sent    . │
      │  . . . . . .  │     │   /////////  │     │  . . . . . . . . . │
      └───────────────┘     └──────────────┘     └───────────────-----┐
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

def detect_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read(1024).lower()
            if '<html>' in content or '<body>' in content:
                return "HTML"
            else:
                return "Text"
    except Exception as e:
        print(f"Error parsing message content {file_path}: {e}")
        return None

def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

def get_mx_servers(domain):
    if domain in _mx_cache:
        return _mx_cache[domain]
    try:
        if domain == 'outlook.com':
            mx_servers = [MX_Server('smtp-mail.outlook.com', 587)]
        elif domain == 'gmail.com':
            mx_servers = [MX_Server('smtp.gmail.com', 587)]
        else:
            socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: _original_socket(family, type_, proto)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 15.0
            resolver.lifetime = 15.0
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
            mx_records = resolver.resolve(domain, 'MX')
            mx_servers = [MX_Server(str(record.exchange).rstrip('.'), 587) for record in sorted(mx_records, key=lambda r: r.preference)]
        _mx_cache[domain] = mx_servers
        print(f"Resolved MX for {domain}: {[s.host for s in mx_servers]}")
        return mx_servers
    except Exception as e:
        print(f"Failed to resolve MX for {domain}: {e}")
        return []
    finally:
        socket.socket = _original_socket

def filter_spam(text):
    spam_words = ["free", "win", "cash", "offer", "prize", "winner", "lottery", "urgent", "info", "contact", "security", "sales", "abuse", "complaints"]
    return not any(word in text.lower() for word in spam_words)

def is_banned_tld(domain):
    banned_tlds = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", "finance", ".us", ".gov"]
    return any(domain.endswith(tld) for tld in banned_tlds)

def group_by_domain(emails):
    grouped_emails = defaultdict(list)
    valid_emails = []
    for email in emails:
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) and filter_spam(email.split('@')[0].strip()):
            domain = email.split('@')[1].strip().lower()
            if not is_banned_tld(domain) and domain not in blocklist:
                grouped_emails[domain].append(email)
                valid_emails.append(email)
            else:
                print(f"Skipping email {email} due to banned TLD or disposable domain: {domain}")
        else:
            print(f"Skipping invalid or spam email: {email}")
    print(f"{len(grouped_emails)} recipient domains found, {len(valid_emails)} valid emails.")
    return valid_emails, grouped_emails

def chunk_list(items, batch_size):
    it = iter(items)
    for first in it:
        yield list(itertools.chain([first], itertools.islice(it, batch_size - 1)))

def personalize_content(content, recipient):
    content = content.replace('[[-Email-]]', recipient)
    content = content.replace('[[-Now-]]', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    return content

def save_valid_email(email, save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(save_dir, "successful_emails.txt")
    with open(file_path, 'a') as file:
        file.write(email + '\n')

def save_failed_email(email, save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(save_dir, "failed_emails.txt")
    with open(file_path, 'a') as file:
        file.write(email + '\n')

def send_mail_batch(mx_server, batch, subject, content, content_type, sender_name, total_sent, total_failed):
    with smtp_lock:
        for recipient in batch:
            with lock:
                if recipient in successful_emails:
                    print(f"Skipping already sent email to {recipient}")
                    continue

            key = (mx_server.host, mx_server.port)
            while not rate_limiter.can_send(mx_server.host, mx_server.port):
                wait_time = rate_limiter.time_until_next_slot(mx_server.host, mx_server.port)
                print(f"Rate limit reached for {mx_server.host}:{mx_server.port}, waiting {wait_time:.2f} seconds")
                time.sleep(wait_time)

            print(f"Attempting to send email to {recipient} via {mx_server.host}:{mx_server.port}")
            try:
                socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: _original_socket(family, type_, proto)
                if mx_server.port == 465:
                    server = smtplib.SMTP_SSL(mx_server.host, mx_server.port, timeout=10)
                    print(f"Connected to {mx_server.host}:{mx_server.port} using SSL")
                else:
                    server = smtplib.SMTP(mx_server.host, mx_server.port, timeout=10)
                    print(f"Connected to {mx_server.host}:{mx_server.port}")
                    try:
                        server.starttls(context=ssl.create_default_context())
                        print(f"STARTTLS initiated for {recipient}")
                    except smtplib.SMTPNotSupportedError:
                        print(f"STARTTLS not supported by {mx_server.host}, proceeding without")
                    server.ehlo('localhost')
                    print(f"EHLO sent for {recipient}")

                # Since sender email = recipient, no login is needed for validation
                msg = MIMEMultipart()
                msg['From'] = formataddr((sender_name, 'local@server235.phx.secureservers.net'))
                msg['To'] = recipient
                msg['Subject'] = subject.replace('[[-Email-]]', recipient)
                personalized_content = personalize_content(content, recipient)
                msg.attach(MIMEText(personalized_content, 'html' if content_type == 'HTML' else 'plain', 'utf-8'))
                server.sendmail(recipient, [recipient], msg.as_string())
                print(f"Email sent successfully to {recipient} via {mx_server.host}:{mx_server.port}")
                rate_limiter.record_send(mx_server.host, mx_server.port)
                with lock:
                    total_sent[0] += 1
                    save_valid_email(recipient)
                    successful_emails.add(recipient)
                server.noop()
                print(f"NOOP sent to keep connection alive for {recipient}")
                server.quit()
            except socket.timeout as e:
                print(f"Timeout connecting to {mx_server.host}:{mx_server.port} for {recipient}: {e}")
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except socket.gaierror as e:
                print(f"DNS resolution error for {mx_server.host}: {e}")
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except smtplib.SMTPRecipientsRefused:
                print(f"Recipient {recipient} refused by {mx_server.host}")
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except smtplib.SMTPNotSupportedError as e:
                print(f"SMTP command not supported for {recipient}: {e}")
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except smtplib.SMTPException as e:
                print(f"SMTP error sending to {recipient}: {e}")
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except Exception as e:
                print(f"Unexpected error for {recipient}: {e}")
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            finally:
                socket.socket = _original_socket

def process_domain(domain, emails, subject, content, content_type, sender_name, total_sent, total_failed):
    print(f"\nProcessing domain: {domain} ({len(emails)} emails)")
    mx_servers = get_mx_servers(domain)
    if not mx_servers:
        print(f"No MX servers found for {domain}")
        for email in emails:
            with lock:
                total_failed[0] += 1
                save_failed_email(email)
        return

    # Try each MX server until one works
    mx_server = None
    for server in mx_servers:
        test_email = emails[0]
        try:
            socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: _original_socket(family, type_, proto)
            with smtplib.SMTP(server.host, server.port, timeout=10) as test_server:
                test_server.ehlo('localhost')
                if server.port != 465:
                    try:
                        test_server.starttls(context=ssl.create_default_context())
                        test_server.ehlo('localhost')
                    except smtplib.SMTPNotSupportedError:
                        pass
                test_server.noop()
                mx_server = server
                break
        except Exception as e:
            print(f"Failed to connect to {server.host}:{server.port} for testing: {e}")
        finally:
            socket.socket = _original_socket
    if not mx_server:
        print(f"No working MX server found for {domain}")
        for email in emails:
            with lock:
                total_failed[0] += 1
                save_failed_email(email)
        return

    print(f"Using MX server {mx_server.host}:{mx_server.port}")
    batch_size = 5
    for batch in chunk_list(emails, batch_size):
        thread = threading.Thread(
            target=send_mail_batch,
            args=(mx_server, batch, subject, content, content_type, sender_name, total_sent, total_failed),
            name=f"Batch-{domain}-{random.randint(1, 10000)}"
        )
        print(f"Starting thread for batch: {thread.name}")
        thread.start()
        threads.append(thread)
        time.sleep(0.1)

def detonate(email_file_path, message_file_path, subject, sender_name):
    rate_limiter.reset()
    print(f"Starting detonate with {email_file_path}, {message_file_path}")
    
    recipients = read_file(email_file_path)
    if not recipients:
        print("No valid recipients loaded.")
        show_error_dialog("No valid recipients loaded.")
        return 0, 0
    
    content_type = detect_content(message_file_path)
    if not content_type:
        print("Invalid message content.")
        show_error_dialog("Invalid message content.")
        return 0, 0
    
    with open(message_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    valid_recipients, grouped_emails = group_by_domain(recipients)
    if not valid_recipients:
        print("No valid recipients after filtering.")
        show_error_dialog("No valid recipients after filtering.")
        return 0, 0

    total_sent = [0]
    total_failed = [0]

    try:
        for domain, emails in grouped_emails.items():
            thread = threading.Thread(
                target=process_domain,
                args=(domain, emails, subject, content, content_type, sender_name, total_sent, total_failed),
                name=f"Domain-{domain}"
            )
            print(f"Starting thread for domain: {domain}")
            thread.start()
            threads.append(thread)
            time.sleep(0.1)

        for thread in threads:
            thread.join()
            print(f"Thread joined: {thread.name}")

        remaining_recipients = [r for r in valid_recipients if r not in successful_emails]
        if remaining_recipients:
            print(f"Redistributing {len(remaining_recipients)} remaining recipients")
            rate_limiter.reset()
            _, grouped_remaining = group_by_domain(remaining_recipients)
            for domain, emails in grouped_remaining.items():
                thread = threading.Thread(
                    target=process_domain,
                    args=(domain, emails, subject, content, content_type, sender_name, total_sent, total_failed),
                    name=f"Domain-Retry-{domain}"
                )
                print(f"Starting retry thread for domain: {domain}")
                thread.start()
                threads.append(thread)
                time.sleep(0.1)

        for thread in threads:
            if thread.is_alive():
                thread.join()
                print(f"Additional thread joined: {thread.name}")
    
    except Exception as e:
        print(f"Error in detonate: {e}")
        show_error_dialog(f"Error in email sending process: {e}")
        return 0, 0

    print(f"Email sending complete. Total sent: {total_sent[0]}, Total failed: {total_failed[0]}")
    messagebox.showinfo("Sending complete", f"Email processed successfully. Sent: {total_sent[0]}, Failed: {total_failed[0]}")
    return total_sent[0], total_failed[0]

def valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def main():
    show_intro()
    email_file = select_emails_file()
    message_file = select_message_file()
    root = Tk()
    root.withdraw()
    subject = simpledialog.askstring("Input", "Enter Email Subject:", parent=root)
    sender_name = simpledialog.askstring("Input", "Enter Sender Name for From header:", parent=root)
    root.destroy()
    if email_file and message_file and subject and sender_name:
        detonate(email_file, message_file, subject, sender_name)
    else:
        show_error_dialog("All inputs (email file, message file, subject, sender name) are required.")
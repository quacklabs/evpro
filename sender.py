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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import shutil
import logging
import threading
from datetime import datetime
from email.utils import formataddr

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
            self.idx = (self.idx + 1) % len(self.spinner)
            time.sleep(1)

class Credentials:
    def __init__(self, host, port, username, password, domain):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain

class RateLimiter:
    def __init__(self, limit_per_hour=30):
        self.limit_per_hour = limit_per_hour
        self.sent_times = defaultdict(deque)  # Track send times per (host, port)
        self.lock = threading.Lock()

    def can_send(self, host, port):
        with self.lock:
            current_time = time.time()
            key = (host, port)
            # Remove timestamps older than 1 hour
            while self.sent_times[key] and current_time - self.sent_times[key][0] > 3600:
                self.sent_times[key].popleft()
            if len(self.sent_times[key]) < self.limit_per_hour:
                self.sent_times[key].append(current_time)
                return True
            return False

    def time_until_next_slot(self, host, port):
        with self.lock:
            key = (host, port)
            if len(self.sent_times[key]) < self.limit_per_hour:
                return 0
            oldest_time = self.sent_times[key][0]
            current_time = time.time()
            return 3600 - (current_time - oldest_time)

class Engine:
    def __init__(self):
        self.logger = logging.getLogger('EmailSenderPro')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)
        self.rate_limiter = RateLimiter(limit_per_hour=30)

    def read_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error("Error reading file %s: %s", file_path, str(e))
            return None

    def filter_spam(self, text):
        spam_words = ["free", "win", "cash", "offer", "prize", "winner", "lottery", "urgent", "info", "contact", "security", "sales", "abuse", "complaints"]
        return not any(word in text.lower() for word in spam_words)

    def is_banned_tld(self, domain):
        banned_tlds = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", "finance", ".us", ".gov"]
        return any(domain.endswith(tld) for tld in banned_tlds)

    def get_mx_servers(self, domain):
        try:
            if domain == 'outlook.com':
                return 'smtp-mail.outlook.com'
            else:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_record = sorted(mx_records, key=lambda r: r.preference)[0]
                return str(mx_record.exchange).rstrip('.')
        except Exception as e:
            self.logger.error("Failed to resolve MX for %s: %s", domain, str(e))
            return None

engine = Engine()
successful_credentials = set()  # Track sent emails to avoid duplicates
threads = []  # Track active threads
lock = threading.Lock()  # Lock for thread-safe updates

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

def select_smtp_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select SMTP Credentials File",
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
        engine.logger.error("Error parsing message content %s: %s", file_path, str(e))
        return None

def load_credentials(file_path):
    smtps = engine.read_file(file_path)
    if smtps is None:
        engine.logger.error("No valid SMTP credentials loaded from file: %s", file_path)
        return []
    engine.logger.info("Loading SMTP credentials from file: %s", file_path)
    credentials = []
    for line in smtps:
        parts = line.strip().split('|')
        if len(parts) == 4:
            username = parts[2].strip()
            if '@' not in username:
                engine.logger.warning("Invalid username format: %s", username)
                continue
            try:
                port = int(parts[1].strip())  # Parse port from file
            except ValueError:
                engine.logger.warning("Invalid port format: %s, skipping %s", parts[1], username)
                continue
            password = parts[3]
            domain = username.split('@')[1].strip().lower()
            details = Credentials(None, port, username, password, domain)
            credentials.append(details)
            engine.logger.debug("Loaded credential: %s for domain %s, port %d", username, domain, port)
        else:
            engine.logger.warning("Invalid credential format: %s", line.strip())
    engine.logger.info("Loaded %d SMTP credentials.", len(credentials))
    return credentials

def load_recipients(file_path):
    emails = engine.read_file(file_path)
    if emails is None:
        engine.logger.error("No valid recipients loaded from file: %s", file_path)
        return []
    engine.logger.info("Loaded %d recipients from file: %s", len(emails), file_path)
    return emails

def group_by_host(credentials):
    grouped = defaultdict(list)
    domain_cache = {}
    for credential in credentials:
        if re.match(r"[^@]+@[^@]+\.[^@]+", credential.username) and engine.filter_spam(credential.username.split('@')[0].strip()):
            domain = credential.username.split('@')[1].strip().lower()
            if not engine.is_banned_tld(domain) and domain not in blocklist:
                if domain in domain_cache:
                    mx_server = domain_cache[domain]
                else:
                    mx_server = engine.get_mx_servers(domain)
                    domain_cache[domain] = mx_server
                    engine.logger.debug("MX lookup for %s: %s", domain, mx_server if mx_server else "None")
                if mx_server:
                    credential.host = mx_server
                    key = (mx_server, credential.port)
                    grouped[key].append(credential)
                    engine.logger.debug("Grouped credential %s under %s:%d", credential.username, mx_server, credential.port)
                else:
                    engine.logger.warning("No MX server found for domain: %s, skipping %s", domain, credential.username)
            else:
                engine.logger.warning("Skipping credential %s due to banned TLD or disposable domain: %s", credential.username, domain)
        else:
            engine.logger.warning("Skipping invalid or spam credential: %s", credential.username)
    engine.logger.info("%d servers found for processing.", len(grouped))
    return grouped

def group_by_domain(emails):
    grouped_emails = defaultdict(list)
    valid_emails = []
    for email in emails:
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) and engine.filter_spam(email.split('@')[0].strip()):
            domain = email.split('@')[1].strip().lower()
            if not engine.is_banned_tld(domain) and domain not in blocklist:
                grouped_emails[domain].append(email)
                valid_emails.append(email)
            else:
                engine.logger.warning("Skipping email %s due to banned TLD or disposable domain: %s", email, domain)
        else:
            engine.logger.warning("Skipping invalid or spam email: %s", email)
    engine.logger.info("%d domains found for recipients, %d valid emails.", len(grouped_emails), len(valid_emails))
    return valid_emails  # Return flat list of valid emails

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

def send_mail_batch(mx_server, port, batch, credential, subject, content, content_type, sender_name, total_sent, total_failed):
    for recipient in batch:
        with lock:  # Thread-safe check
            credential_key = f"{credential.username}:{recipient}"
            if credential_key in successful_credentials:
                engine.logger.info("Skipping already sent email from %s to %s", credential.username, recipient)
                continue

        # Check rate limit
        while not engine.rate_limiter.can_send(mx_server, port):
            wait_time = engine.rate_limiter.time_until_next_slot(mx_server, port)
            engine.logger.info("Rate limit reached for %s:%d, waiting %.2f seconds", mx_server, port, wait_time)
            time.sleep(wait_time)

        spinner = Spinner(f"Sending email from {credential.username} to {recipient}...")
        spinner.start()
        engine.logger.info("Attempting SMTP connection for %s to %s on %s:%d", credential.username, recipient, mx_server, port)
        try:
            # Use SMTP_SSL for port 465, SMTP with STARTTLS for others
            if port == 465:
                server = smtplib.SMTP_SSL(mx_server, port, timeout=10)
                engine.logger.debug("Connected to SMTP server %s:%d for %s using SSL", mx_server, port, credential.username)
                server.ehlo(f"{credential.domain}")
                engine.logger.debug("EHLO sent for %s", credential.domain)
            else:
                server = smtplib.SMTP(mx_server, port, timeout=10)
                engine.logger.debug("Connected to SMTP server %s:%d for %s", mx_server, port, credential.username)
                server.ehlo(f"{credential.domain}")
                engine.logger.debug("EHLO sent for %s", credential.domain)
                server.starttls()
                engine.logger.debug("STARTTLS initiated for %s", credential.username)
                server.ehlo(f"{credential.domain}")
                engine.logger.debug("Second EHLO sent for %s", credential.domain)
            
            server.login(credential.username, credential.password)
            engine.logger.info("Successfully logged in for %s", credential.username)
            
            msg = MIMEMultipart()
            msg['From'] = formataddr((sender_name, credential.username))  # Use provided sender_name
            msg['To'] = recipient
            msg['Subject'] = subject.replace('[[-Email-]]', recipient)
            personalized_content = personalize_content(content, recipient)
            msg.attach(MIMEText(personalized_content, 'html' if content_type == 'HTML' else 'plain'))
            server.sendmail(credential.username, [recipient], msg.as_string())
            engine.logger.info("Email sent successfully from %s to %s", credential.username, recipient)
            with lock:  # Thread-safe update
                total_sent[0] += 1
                save_valid_email(recipient)
                successful_credentials.add(credential_key)
                # Add delay after every 100 emails
                if total_sent[0] % 100 == 0:
                    delay_minutes = random.uniform(1, 5)
                    engine.logger.info("Pausing for %.2f minutes after %d emails", delay_minutes, total_sent[0])
                    time.sleep(delay_minutes * 60)
            server.noop()
            engine.logger.debug("NOOP sent to keep connection alive for %s", credential.username)
            server.quit()
        except (smtplib.SMTPException, socket.error) as e:
            engine.logger.error("SMTP send failed for %s to %s: %s", credential.username, recipient, str(e))
            with lock:  # Thread-safe update
                total_failed[0] += 1
                save_failed_email(recipient)
        except Exception as e:
            engine.logger.error("Unexpected error for %s to %s: %s", credential.username, recipient, str(e))
            with lock:  # Thread-safe update
                total_failed[0] += 1
                save_failed_email(recipient)
        finally:
            spinner.stop()

def distribute_recipients(recipients, grouped_credentials):
    """Distribute recipients evenly across credentials for load balancing."""
    assignments = []
    recipient_count = len(recipients)
    total_credentials = sum(len(creds) for creds in grouped_credentials.values())
    
    if total_credentials == 0:
        return assignments

    # Calculate recipients per credential
    recipients_per_credential = max(1, recipient_count // total_credentials)
    
    recipient_iter = iter(recipients)
    for (host, port), credentials in grouped_credentials.items():
        for credential in credentials:
            # Assign up to recipients_per_credential recipients to this credential
            batch = list(itertools.islice(recipient_iter, recipients_per_credential))
            if batch:
                assignments.append(((host, port), credential, batch))
    # Assign any remaining recipients to a random credential
    remaining = list(recipient_iter)
    if remaining:
        (host, port), credentials = random.choice(list(grouped_credentials.items()))
        credential = random.choice(credentials)
        assignments.append(((host, port), credential, remaining))
    
    return assignments

def detonate(email_file_path, smtp_file_path, message_file_path, subject):
    # Prompt for sender name after subject
    
    root = Tk()
    root.withdraw()
    sender_name = simpledialog.askstring("Input", "Enter Sender Name for From header:", parent=root)
    root.destroy()
    if not sender_name:
        engine.logger.error("No sender name provided. Exiting.")
        messagebox.showerror("Error", "Sender name is required.")
        return 0, 0

    recipients = load_recipients(email_file_path)
    if not recipients:
        engine.logger.error("No valid recipients loaded. Exiting.")
        messagebox.showerror("Error", "No valid recipients loaded.")
        return 0, 0
    
    credentials = load_credentials(smtp_file_path)
    if not credentials:
        engine.logger.error("No valid SMTP credentials loaded. Exiting.")
        messagebox.showerror("Error", "No valid SMTP credentials loaded.")
        return 0, 0
    
    content_type = detect_content(message_file_path)
    if not content_type:
        engine.logger.error("Invalid message content. Exiting.")
        messagebox.showerror("Error", "Invalid message content.")
        return 0, 0
    
    with open(message_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    grouped_credentials = group_by_host(credentials)
    valid_recipients = group_by_domain(recipients)  # Returns a flat list of valid emails
    total_sent = [0]  # Use list to allow modification in threads
    total_failed = [0]  # Use list to allow modification in threads
    batch_number = 1

    # Distribute recipients across credentials for load balancing
    assignments = distribute_recipients(valid_recipients, grouped_credentials)
    engine.logger.info("Assigned %d recipients across %d credentials", len(valid_recipients), len(assignments))

    # Process each assignment
    for (host, port), credential, recipient_batch in assignments:
        if not recipient_batch:
            engine.logger.info("No recipients assigned to %s, skipping.", credential.username)
            continue
        # Split recipients into smaller batches (e.g., 5 emails per batch)
        for batch in chunk_list(recipient_batch, 5):
            engine.logger.info("Processing batch %d for %s:%d from %s with %d recipients", 
                             batch_number, host, port, credential.username, len(batch))
            thread = threading.Thread(
                target=send_mail_batch,
                args=(host, port, batch, credential, subject, content, content_type, sender_name, total_sent, total_failed),
                name=f"Batch-{batch_number}-{credential.username}"
            )
            thread.start()
            threads.append(thread)
            batch_number += 1

    for thread in threads:
        thread.join()
        engine.logger.debug("Thread joined: %s", thread.name)
    
    engine.logger.info("Email sending complete. Total sent: %d, Total failed: %d", total_sent[0], total_failed[0])
    messagebox.showinfo("Sending complete", f"Email processed successfully. Sent: {total_sent[0]}, Failed: {total_failed[0]}")
    return total_sent[0], total_failed[0]  # Return counts

def valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None
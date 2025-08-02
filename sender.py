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
import logging
import threading
from datetime import datetime
from email.utils import formataddr

try:
    from disposable_email_domains import blocklist
except ImportError:
    blocklist = set()
    logging.warning("disposable_email_domains module not found. Disposable domain filtering disabled.")

class Credentials:
    def __init__(self, host, port, username, password, domain):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain

class RateLimiter:
    def __init__(self, default_limit_per_hour=43, enabled=True):
        self.default_limit_per_hour = default_limit_per_hour
        self.enabled = enabled
        self.sent_times = defaultdict(deque)
        self.limits = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger('EmailSenderPro')

    def set_limit(self, host, port, limit):
        with self.lock:
            self.limits[(host, port)] = limit
            self.logger.info("Set rate limit for %s:%d to %d emails per hour", host, port, limit)

    def reset(self):
        with self.lock:
            self.sent_times.clear()
            self.logger.info("Rate limiter reset. All sent_times cleared.")

    def can_send(self, host, port):
        if not self.enabled:
            self.logger.debug("Rate limiting disabled, allowing send for %s:%d", host, port)
            return True
        with self.lock:
            current_time = time.time()
            key = (host, port)
            limit = self.limits.get(key, self.default_limit_per_hour)
            while self.sent_times[key] and current_time - self.sent_times[key][0] > 3600:
                self.sent_times[key].popleft()
            current_count = len(self.sent_times[key])
            self.logger.debug("Rate limiter check for %s:%d: %d/%d emails sent in last hour", 
                             host, port, current_count, limit)
            if current_count >= limit:
                self.logger.warning("Rate limit reached for %s:%d, %d emails sent", 
                                   host, port, current_count)
                return False
            self.logger.debug("Allowing send for %s:%d, current count: %d", 
                             host, port, current_count)
            return True

    def record_send(self, host, port):
        if not self.enabled:
            self.logger.debug("Rate limiting disabled, skipping record for %s:%d", host, port)
            return
        with self.lock:
            key = (host, port)
            self.sent_times[key].append(time.time())
            self.logger.debug("Recorded send for %s:%d, new count: %d", 
                             host, port, len(self.sent_times[key]))

    def time_until_next_slot(self, host, port):
        if not self.enabled:
            self.logger.debug("Rate limiting disabled, no wait needed for %s:%d", host, port)
            return 0
        with self.lock:
            key = (host, port)
            limit = self.limits.get(key, self.default_limit_per_hour)
            current_count = len(self.sent_times[key])
            if current_count < limit:
                self.logger.debug("No wait needed for %s:%d, %d/%d emails sent", 
                                 host, port, current_count, limit)
                return 0
            oldest_time = self.sent_times[key][0]
            current_time = time.time()
            wait_time = 3600 - (current_time - oldest_time)
            self.logger.info("Waiting %.2f seconds for next slot for %s:%d", wait_time, host, port)
            return wait_time

class Engine:
    def __init__(self):
        self.logger = logging.getLogger('EmailSenderPro')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)
        self.rate_limiter = RateLimiter(default_limit_per_hour=43, enabled=True)  # Enabled by default, set in detonate
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 15.0
        self.resolver.lifetime = 15.0
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        self.semaphores = defaultdict(lambda: threading.Semaphore(1))

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
        banned_tlds = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", ".finance", ".us", ".gov"]
        return any(domain.endswith(tld) for tld in banned_tlds)

    def get_mx_servers(self, domain):
        try:
            if domain == 'outlook.com':
                return 'smtp-mail.outlook.com'
            elif domain == 'gmail.com':
                return 'smtp.gmail.com'
            else:
                mx_records = self.resolver.resolve(domain, 'MX')
                mx_record = sorted(mx_records, key=lambda r: r.preference)[0]
                mx_server = str(mx_record.exchange).rstrip('.')
                self.logger.debug("Resolved MX for %s: %s", domain, mx_server)
                return mx_server
        except Exception as e:
            self.logger.error("Failed to resolve MX for %s: %s. Using fallback.", domain, str(e))
            return None

engine = Engine()
successful_credentials = set()
threads = []
lock = threading.Lock()

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
            smtp_host = parts[0].strip() if parts[0].strip() else None
            try:
                port = int(parts[1].strip())
            except ValueError:
                engine.logger.warning("Invalid port format: %s, skipping line", parts[1])
                continue
            username = parts[2].strip()
            if '@' not in username:
                engine.logger.warning("Invalid username format: %s", username)
                continue
            password = parts[3].strip()
            domain = username.split('@')[1].strip().lower()
            details = Credentials(smtp_host, port, username, password, domain)
            credentials.append(details)
            engine.logger.debug("Loaded credential: %s for domain %s, port %d, smtp_host %s", 
                              username, domain, port, smtp_host if smtp_host else "None")
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
                if credential.host:
                    mx_server = credential.host
                    engine.logger.debug("Using provided SMTP host %s for %s", mx_server, credential.username)
                else:
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
                    engine.logger.debug("Grouped credential %s under sender SMTP %s:%d", 
                                      credential.username, mx_server, credential.port)
                else:
                    engine.logger.warning("No SMTP server found for domain %s, skipping %s", 
                                        domain, credential.username)
            else:
                engine.logger.warning("Skipping credential %s due to banned TLD or disposable domain: %s", 
                                    credential.username, domain)
        else:
            engine.logger.warning("Skipping invalid or spam credential: %s", credential.username)
    engine.logger.info("Grouped %d credentials into %d sender SMTP servers.", len(credentials), len(grouped))
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
    engine.logger.info("%d recipient domains found, %d valid emails.", len(grouped_emails), len(valid_emails))
    return valid_emails

def chunk_list(items, batch_size):
    it = iter(items)
    for first in it:
        yield list(itertools.chain([first], itertools.islice(it, batch_size - 1)))

def personalize_content(content, recipient):
    content = content.replace('[[-Email-]]', recipient)
    content = content.replace('[[-Now-]]', datetime.now().strftime('%Y-%m-d %H:%M:%S'))
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

def send_mail_batch(mx_server, port, batch, credential, subject, content, content_type, sender_name, total_sent, total_failed, use_rate_limiter):
    with engine.semaphores[(mx_server, port)]:
        for recipient in batch:
            with lock:
                credential_key = f"{credential.username}:{recipient}"
                if credential_key in successful_credentials:
                    engine.logger.info("Skipping already sent email from %s to %s", credential.username, recipient)
                    continue

            key = (mx_server, port)
            if use_rate_limiter:
                limit = engine.rate_limiter.limits.get(key, engine.rate_limiter.default_limit_per_hour)
                current_count = len(engine.rate_limiter.sent_times[key])
                engine.logger.debug("Pre-send check for %s:%d: %d/%d emails in queue", 
                                  mx_server, port, current_count, limit)

                while not engine.rate_limiter.can_send(mx_server, port):
                    wait_time = engine.rate_limiter.time_until_next_slot(mx_server, port)
                    engine.logger.info("Rate limit reached for sender SMTP %s:%d, waiting %.2f seconds", mx_server, port, wait_time)
                    time.sleep(wait_time)

            engine.logger.info("Attempting to send email from %s to %s via SMTP %s:%d", 
                              credential.username, recipient, mx_server, port)
            try:
                if port == 465:
                    server = smtplib.SMTP_SSL(mx_server, port, timeout=10)
                    engine.logger.debug("Connected to sender SMTP %s:%d for %s using SSL", 
                                      mx_server, port, credential.username)
                    server.ehlo(f"{credential.domain}")
                    engine.logger.debug("EHLO sent for %s", credential.domain)
                else:
                    server = smtplib.SMTP(mx_server, port, timeout=10)
                    engine.logger.debug("Connected to sender SMTP %s:%d for %s", 
                                      mx_server, port, credential.username)
                    server.ehlo(f"{credential.domain}")
                    engine.logger.debug("EHLO sent for %s", credential.domain)
                    server.starttls()
                    engine.logger.debug("STARTTLS initiated for %s", credential.username)
                    server.ehlo(f"{credential.domain}")
                    engine.logger.debug("Second EHLO sent for %s", credential.domain)
                
                server.login(credential.username, password=credential.password)
                engine.logger.info("Successfully logged in for %s", credential.username)
                
                msg = MIMEMultipart()
                msg['From'] = formataddr((sender_name, credential.username))
                msg['To'] = recipient
                msg['Subject'] = subject.replace('[[-Email-]]', recipient)
                personalized_content = personalize_content(content, recipient)
                msg.attach(MIMEText(personalized_content, 'html', 'utf-8'))
                server.sendmail(credential.username, [recipient], msg.as_string())
                engine.logger.info("Email sent successfully from %s to %s via %s:%d", 
                                  credential.username, recipient, mx_server, port)
                if use_rate_limiter:
                    engine.rate_limiter.record_send(mx_server, port)
                with lock:
                    total_sent[0] += 1
                    save_valid_email(recipient)
                    successful_credentials.add(credential_key)
                server.noop()
                engine.logger.debug("NOOP sent to keep connection alive for %s", credential.username)
                server.quit()
            except smtplib.SMTPAuthenticationError as e:
                engine.logger.error("Authentication failed for %s on %s:%d: %s", 
                                   credential.username, mx_server, port, str(e))
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except smtplib.SMTPConnectError as e:
                engine.logger.error("Connection failed to %s:%d for %s: %s", 
                                   mx_server, port, credential.username, str(e))
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except socket.timeout as e:
                engine.logger.error("Timeout connecting to %s:%d for %s: %s", 
                                   mx_server, port, credential.username, str(e))
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)
            except Exception as e:
                engine.logger.error("Unexpected error for %s to %s: %s", 
                                   credential.username, recipient, str(e))
                with lock:
                    total_failed[0] += 1
                    save_failed_email(recipient)

def distribute_recipients(recipients, grouped_credentials, use_rate_limiter):
    assignments = []
    recipient_count = len(recipients)
    available_servers = [(host, port) for host, port in grouped_credentials.keys()]
    
    if not available_servers:
        engine.logger.error("No sender SMTP servers available for distribution.")
        return assignments

    batch_size = 1 if recipient_count <= 10 else 5
    random.shuffle(recipients)
    recipient_iter = iter(recipients)
    server_queue = deque(available_servers)
    iteration_count = 0

    engine.logger.debug("Starting distribution for %d recipients across %d SMTP servers", 
                       recipient_count, len(available_servers))

    while recipient_iter:
        iteration_count += 1
        if iteration_count > recipient_count * 2:
            engine.logger.error("Distribution loop exceeded max iterations. Possible infinite loop.")
            break

        try:
            host, port = server_queue[0]
            credentials = grouped_credentials[(host, port)]
            if not credentials:
                engine.logger.warning("No credentials for sender SMTP %s:%d, rotating.", host, port)
                server_queue.popleft()
                if not server_queue:
                    engine.logger.error("No more SMTP servers available. Stopping distribution.")
                    break
                continue
            
            if use_rate_limiter:
                limit = engine.rate_limiter.limits.get((host, port), engine.rate_limiter.default_limit_per_hour)
                current_count = len(engine.rate_limiter.sent_times[(host, port)])
                engine.logger.debug("Distribute check for %s:%d: %d/%d emails in queue", 
                                  host, port, current_count, limit)
                
                if not engine.rate_limiter.can_send(host, port):
                    wait_time = engine.rate_limiter.time_until_next_slot(host, port)
                    engine.logger.info("Sender SMTP %s:%d is rate-limited, waiting %.2f seconds. Rotating.", 
                                      host, port, wait_time)
                    server_queue.rotate(1)
                    continue
            
            credential = random.choice(credentials)
            batch = list(itertools.islice(recipient_iter, batch_size))
            if batch:
                assignments.append(((host, port), credential, batch))
                engine.logger.info("Assigned batch of %d recipients to sender SMTP %s:%d (%s)", 
                                  len(batch), host, port, credential.username)
            else:
                engine.logger.debug("No more recipients to assign for %s:%d", host, port)
                break
            
            server_queue.rotate(1)
            
        except StopIteration:
            engine.logger.debug("Recipient iterator exhausted. Ending distribution.")
            break
        except Exception as e:
            engine.logger.error("Error in distribution loop: %s", str(e))
            break

    engine.logger.info("Distributed %d recipients across %d assignments using sender SMTP servers.", 
                      recipient_count, len(assignments))
    return assignments

def detonate(email_file_path, smtp_file_path, message_file_path, subject):
    root = Tk()
    root.withdraw()
    rate_limit_response = simpledialog.askstring("Input", "Apply rate limiting? (yes/no):", parent=root)
    use_rate_limiter = rate_limit_response.lower() == 'yes' if rate_limit_response else True
    engine.rate_limiter.enabled = use_rate_limiter
    engine.logger.info("Rate limiting %s", "enabled" if use_rate_limiter else "disabled")
    if use_rate_limiter:
        engine.rate_limiter.reset()
    
    sender_name = simpledialog.askstring("Input", "Enter Sender Name for From header:", parent=root)
    root.destroy()
    if not sender_name:
        engine.logger.error("No sender name provided. Exiting.")
        show_error_dialog("Sender name is required.")
        return 0, 0

    recipients = load_recipients(email_file_path)
    if not recipients:
        engine.logger.error("No valid recipients loaded. Exiting.")
        show_error_dialog("No valid recipients loaded.")
        return 0, 0
    
    credentials = load_credentials(smtp_file_path)
    if not credentials:
        engine.logger.error("No valid SMTP credentials loaded. Exiting.")
        show_error_dialog("No valid SMTP credentials loaded.")
        return 0, 0
    
    content_type = detect_content(message_file_path)
    if not content_type:
        engine.logger.error("Invalid message content. Exiting.")
        show_error_dialog("Invalid message content.")
        return 0, 0
    
    with open(message_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    grouped_credentials = group_by_host(credentials)
    if not grouped_credentials:
        engine.logger.error("No valid SMTP servers after grouping. Exiting.")
        show_error_dialog("No valid SMTP servers available. Check credentials.")
        return 0, 0

    valid_recipients = group_by_domain(recipients)
    if not valid_recipients:
        engine.logger.error("No valid recipients after filtering. Exiting.")
        show_error_dialog("No valid recipients after filtering.")
        return 0, 0

    total_sent = [0]
    total_failed = [0]
    batch_number = 1

    try:
        assignments = distribute_recipients(valid_recipients, grouped_credentials, use_rate_limiter)
        engine.logger.info("Assigned %d recipients across %d batches", len(valid_recipients), len(assignments))

        if not assignments:
            engine.logger.error("No assignments created. Check SMTP credentials and recipient list.")
            show_error_dialog("No assignments created. Check SMTP credentials and recipient list.")
            return 0, 0

        for (host, port), credential, recipient_batch in assignments:
            if not recipient_batch:
                engine.logger.info("No recipients assigned to %s, skipping.", credential.username)
                continue
            if use_rate_limiter:
                engine.rate_limiter.reset()
            engine.logger.info("Starting batch %d for sender SMTP %s:%d from %s with %d recipients", 
                             batch_number, host, port, credential.username, len(recipient_batch))
            thread = threading.Thread(
                target=send_mail_batch,
                args=(host, port, recipient_batch, credential, subject, content, content_type, sender_name, total_sent, total_failed, use_rate_limiter),
                name=f"Batch-{batch_number}-{credential.username}"
            )
            engine.logger.debug("Starting thread for batch %d: %s", batch_number, thread.name)
            thread.start()
            threads.append(thread)
            batch_number += 1
            time.sleep(0.1)

        for thread in threads:
            thread.join()
            engine.logger.debug("Thread joined: %s", thread.name)

        remaining_recipients = [r for r in valid_recipients if not any(f"{c.username}:{r}" in successful_credentials 
                                                                      for c in sum(grouped_credentials.values(), []))]
        if remaining_recipients:
            engine.logger.info("Redistributing %d remaining recipients due to rate limits or failures.", 
                              len(remaining_recipients))
            if use_rate_limiter:
                engine.rate_limiter.reset()
            additional_assignments = distribute_recipients(remaining_recipients, grouped_credentials, use_rate_limiter)
            for (host, port), credential, batch in additional_assignments:
                engine.logger.info("Starting additional batch %d for sender SMTP %s:%d from %s with %d recipients", 
                                  batch_number, host, port, credential.username, len(batch))
                thread = threading.Thread(
                    target=send_mail_batch,
                    args=(host, port, batch, credential, subject, content, content_type, sender_name, total_sent, total_failed, use_rate_limiter),
                    name=f"Batch-{batch_number}-{credential.username}"
                )
                engine.logger.debug("Starting thread for additional batch %d: %s", batch_number, thread.name)
                thread.start()
                threads.append(thread)
                batch_number += 1
                time.sleep(0.1)

        for thread in threads:
            if thread.is_alive():
                thread.join()
                engine.logger.debug("Additional thread joined: %s", thread.name)
    
    except Exception as e:
        engine.logger.error("Error in detonate: %s", str(e))
        show_error_dialog(f"Error in email sending process: {str(e)}")
        return 0, 0

    engine.logger.info("Email sending complete. Total sent: %d, Total failed: %d", total_sent[0], total_failed[0])
    messagebox.showinfo("Sending complete", f"Email processed successfully. Sent: {total_sent[0]}, Failed: {total_failed[0]}")
    return total_sent[0], total_failed[0]

def valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def main():
    show_intro()
    email_file = select_emails_file()
    smtp_file = select_smtp_file()
    message_file = select_message_file()
    subject = simpledialog.askstring("Input", "Enter Email Subject:", parent=Tk())
    if email_file and smtp_file and message_file and subject:
        detonate(email_file, smtp_file, message_file, subject)
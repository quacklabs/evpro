import re
import dns.resolver
import threading
import queue
import os
import tkinter as tk
from tkinter import filedialog
from typing import List
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

OUTLOOK_MX_KEYWORDS = [
    "outlook.com", "outlook.office365.com", "hotmail.com",
    "protection.outlook.com", "mail.eo.outlook.com",
    "olc.protection.outlook.com"
]


class FastOutlookEmailValidator:
    def __init__(self, thread_count: int = 10):
        self.outlook_mx_keywords = OUTLOOK_MX_KEYWORDS
        self.email_queue = queue.Queue()
        self.valid_emails = []
        self.lock = threading.Lock()
        self.thread_count = thread_count

    def select_email_file(self) -> str:
        root = tk.Tk()
        root.withdraw()
        return filedialog.askopenfilename(
            title="Select Email List File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

    def read_emails(self, path: str) -> List[str]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                emails = list(set([line.strip() for line in f if line.strip()]))
                logging.info(f"{len(emails)} unique emails loaded.")
                return emails
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            return []

    def is_valid_syntax(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def is_outlook_mx(self, domain: str) -> bool:
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            for record in mx_records:
                mx_host = str(record.exchange).lower().rstrip('.')
                if any(keyword in mx_host for keyword in self.outlook_mx_keywords):
                    return True
        except Exception as e:
            logging.debug(f"MX lookup failed for {domain}: {e}")
        return False

    def worker(self):
        while True:
            try:
                email = self.email_queue.get(timeout=5)
            except queue.Empty:
                break

            if not self.is_valid_syntax(email):
                self.email_queue.task_done()
                continue

            domain = email.split('@')[1].lower()
            if self.is_outlook_mx(domain):
                with self.lock:
                    self.valid_emails.append(email)
                    logging.info(f"[VALID] {email}")
            self.email_queue.task_done()

    def run(self, emails: List[str]):
        for email in emails:
            self.email_queue.put(email)

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def save_results(self, output_path: str):
        with open(output_path, 'w', encoding='utf-8') as f:
            for email in sorted(self.valid_emails):
                f.write(email + '\n')
        logging.info(f"Saved {len(self.valid_emails)} validated emails to {output_path}")


def main():
    validator = FastOutlookEmailValidator(thread_count=10)

    email_file = validator.select_email_file()
    if not email_file:
        logging.warning("No email file selected.")
        return

    emails = validator.read_emails(email_file)
    if not emails:
        logging.warning("No emails to validate.")
        return

    validator.run(emails)

    output_file = os.path.expanduser("~/Desktop/outlook_valid_emails.txt")
    validator.save_results(output_file)
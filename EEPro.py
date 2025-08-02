import os
import re
import requests
import sys
import socket
import socks
from tkinter import Tk, messagebox, filedialog
import smtplib
from disposable_email_domains import blocklist
from collections import defaultdict
import time
import concurrent.futures
import threading
import queue
import itertools
import dns.resolver
import base64
import ssl
from servers import Proxy, MX_Server
import logging

class Engine:
    def __init__(self, logger=None):
        if logger is None:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s [%(threadName)s] %(message)s",
                handlers=[logging.StreamHandler()]
            )
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        self.last_proxy = None
        # Store original socket to restore after forcing IPv4
        self._original_socket = socket.socket

    def select_file(self, file_types):
        root = Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title="Select file", filetypes=file_types)
        return file_path

    def read_file(self, file_path):
        with open(file_path, 'r') as f:
            for line in f:
                yield line.strip()

    def fetch_proxy(self, max_retries=3):
        """Fetch proxies with retry logic and force IPv4."""
        for attempt in range(max_retries):
            try:
                # Force IPv4 for requests
                socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: self._original_socket(family, type_, proto)
                headers = {"Content-type": "application/json", "Accept": "application/json"}
                api_url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json"
                response = requests.get(api_url, headers=headers, timeout=10)
                response.raise_for_status()
                proxies = response.json()
                # Filter for SOCKS4/SOCKS5 only
                valid_proxies = [Proxy(proxy['ip'], proxy['port'], proxy['protocol']) for proxy in proxies if proxy['protocol'].lower() in ['socks4', 'socks5']]
                self.logger.info(f"Fetched {len(proxies)} proxies, {len(valid_proxies)} SOCKS4/SOCKS5 proxies")
                return valid_proxies
            except Exception as e:
                self.logger.error(f"Failed to get proxies (attempt {attempt + 1}/{max_retries}): {e}")
                time.sleep(2)
            finally:
                socket.socket = self._original_socket  # Restore original socket
        return []

    def test_proxy(self, host, port, proxy):
        """Test if a proxy supports SMTP connection to the given host and port."""
        try:
            if proxy.protocol == 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
            elif proxy.protocol == 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
            else:
                self.logger.error(f"Unsupported proxy protocol: {proxy.protocol}")
                return False

            socket.socket = socks.socksocket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.close()
            return True
        except Exception as e:
            self.logger.debug(f"Proxy {proxy.host}:{proxy.port} failed for {host}:{port}: {e}")
            return False
        finally:
            socket.socket = self._original_socket

    def find_valid_proxy(self, host, port, proxies):
        """Find a valid SOCKS proxy for the given SMTP server."""
        current_count = 0
        for idx, proxy in enumerate(proxies, start=1):
            current_count = idx
            try:
                status = self.test_proxy(host, port, proxy)
                print(f"\rTrying proxy ({proxy.protocol}): {proxy.host}:{proxy.port}:- {idx}/{len(proxies)} | ({int((current_count / len(proxies)) * 100)}%)\033[K", end="")
                if status:
                    print(f"\nProxy found: {proxy.host}:{proxy.port} - with protocol: {proxy.protocol}")
                    self.last_proxy = proxy
                    return proxy
            except Exception as e:
                self.logger.debug(f"Proxy {proxy.host}:{proxy.port} failed for {host}:{port}: {e}")
                continue
        print("\nNo valid proxy found")
        return None

    def check_smtp_port(self, host, port, proxy):
        """Check if an SMTP connection can be established with the given proxy."""
        try:
            if proxy.protocol == 'socks4':
                socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
            elif proxy.protocol == 'socks5':
                socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
            else:
                self.logger.error(f"Unsupported proxy protocol: {proxy.protocol}")
                return False

            socks.wrapmodule(smtplib)
            socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: self._original_socket(family, type_, proto)
            context = ssl.create_default_context()
            with smtplib.SMTP(host, port, timeout=6) as server:
                server.ehlo('localhost')
                if port != 465:
                    server.starttls(context=context)
                    server.ehlo('localhost')
                server.noop()
                return True
        except socket.timeout:
            self.logger.debug(f"Timeout connecting to {host}:{port} with proxy {proxy.host}:{proxy.port}")
            return False
        except socks.GeneralProxyError as e:
            self.logger.debug(f"Proxy error for {host}:{port} with proxy {proxy.host}:{proxy.port}: {e}")
            return False
        except socket.error as e:
            self.logger.debug(f"Socket error for {host}:{port} with proxy {proxy.host}:{proxy.port}: {e}")
            return False
        except smtplib.SMTPException as e:
            self.logger.debug(f"SMTP error for {host}:{port} with proxy {proxy.host}:{proxy.port}: {e}")
            return False
        except Exception as e:
            self.logger.debug(f"Unexpected error for {host}:{port} with proxy {proxy.host}:{proxy.port}: {e}")
            return False
        finally:
            socket.socket = self._original_socket

    def test_smtp_login(self, smtp_host, smtp_port, username, password, proxy, protocol):
        """Test SMTP login credentials."""
        server = MX_Server(smtp_host, smtp_port)
        try:
            if protocol == "ssl":
                connection = self.connect_ssl(server, proxy)
            elif protocol == "tls":
                connection = self.connect_tls(server, proxy)
            else:
                self.logger.error(f"Unsupported protocol: {protocol}")
                return False

            if connection is None:
                self.logger.error(f"Unable to establish SMTP connection: {smtp_host}:{smtp_port} - protocol: {protocol}")
                return False

            username64 = base64.b64encode(username.encode("utf-8")).decode("utf-8")
            password64 = base64.b64encode(password.encode("utf-8")).decode("utf-8")
            commands = [
                f"AUTH LOGIN\r\n",
                f"{username64}\r\n",
                f"{password64}\r\n",
                f"MAIL FROM:<{username}>\r\n",
            ]

            for cmd in commands:
                connection.sendall(cmd.encode())
                response = connection.recv(1024).decode('utf-8')
                if "550" in response or "5.0.0" in response or "500" in response:
                    self.logger.error(f"Server Error: {response}")
                    return False

            connection.sendall("QUIT\r\n".encode())
            connection.close()
            return True
        except Exception as e:
            self.logger.error(f'SMTP login failed: {e}')
            return False

    def group_by_domain(self, emails):
        """Group emails by domain, filtering out spam and banned TLDs."""
        grouped_emails = defaultdict(list)
        for email in emails:
            if re.match(r"[^@]+@[^@]+\.[^@]+", email) and self.filter_spam(email.split('@')[0].strip()):
                domain = email.split('@')[1].strip().lower()
                if not self.is_banned_tld(domain):
                    grouped_emails[domain].append(email)

        valid_email_groups = {}
        for domain, domain_emails in grouped_emails.items():
            if domain not in blocklist:
                valid_email_groups[domain] = domain_emails

        return valid_email_groups

    def is_banned_tld(self, domain):
        """Check if domain has a banned TLD."""
        banned_tlds = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", ".finance", ".gov", ".gov.ng", ".gov.us"]
        return any(domain.endswith(tld) for tld in banned_tlds)

    def filter_spam(self, email):
        """Filter out emails with spam-related keywords."""
        spam_words = [
            "free", "win", "cash", "offer",
            "prize", "winner", "lottery",
            "urgent", "security", "abuse",
            "complaints", "webmaster", "report",
        ]
        return not any(word in email.lower() for word in spam_words)

    def get_mx_servers(self, domain):
        """Resolve MX servers for a domain."""
        try:
            if domain == 'outlook.com':
                return ['smtp-mail.outlook.com']
            else:
                socket.socket = lambda family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0: self._original_socket(family, type_, proto)
                mx_records = dns.resolver.resolve(domain, 'MX')
                return [str(record.exchange).rstrip('.') for record in sorted(mx_records, key=lambda r: r.preference)]
        except Exception as e:
            self.logger.error(f"Failed to get MX servers for {domain}: {e}")
            return [domain]
        finally:
            socket.socket = self._original_socket

    def connect_ssl(self, mx_server, proxy):
        """Establish an SSL SMTP connection."""
        try:
            if proxy and proxy.protocol in ['socks4', 'socks5']:
                socks.set_default_proxy(socks.SOCKS4 if proxy.protocol == 'socks4' else socks.SOCKS5, proxy.host, proxy.port)
                socket.socket = socks.socksocket
            else:
                socket.socket = self._original_socket

            context = ssl.create_default_context()
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn = context.wrap_socket(conn, server_hostname=mx_server.host)
            conn.settimeout(6)
            conn.connect((mx_server.host, mx_server.port))
            return conn
        except Exception as e:
            self.logger.error(f"SSL connection failed to {mx_server.host}:{mx_server.port}: {e}")
            return None
        finally:
            socket.socket = self._original_socket

    def connect_tls(self, mx_server, proxy):
        """Establish a TLS SMTP connection."""
        try:
            if proxy and proxy.protocol in ['socks4', 'socks5']:
                socks.set_default_proxy(socks.SOCKS4 if proxy.protocol == 'socks4' else socks.SOCKS5, proxy.host, proxy.port)
                socket.socket = socks.socksocket
            else:
                socket.socket = self._original_socket

            context = ssl.create_default_context()
            with smtplib.SMTP(mx_server.host, mx_server.port, timeout=6) as server:
                server.ehlo('localhost')
                server.starttls(context=context)
                server.ehlo('localhost')
                return server.sock
        except Exception as e:
            self.logger.error(f"TLS connection failed to {mx_server.host}:{mx_server.port}: {e}")
            return None
        finally:
            socket.socket = self._original_socket
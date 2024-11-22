import os
import re
import requests
import sys
import socket
import socks
from tkinter import Tk, messagebox, filedialog
# from smtplib import SMTP
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

from handler import Sender, Validator
import yagmail
import logging

class Engine:

	def __init__(self, logger = None):
		if logger == None:
			# Set up centralized logging
			logging.basicConfig(
				level=logging.INFO,
				format="%(asctime)s [%(threadName)s] %(message)s",
				handlers=[logging.StreamHandler()]
			)
			self.logger = logging.getLogger(__name__)
		else:
			self.logger = logger

		self.last_proxy = None

	def select_file(self, file_types):
		root = Tk()
		root.withdraw()

		file_path = filedialog.askopenfilename(title="Select file", filetypes=file_types)

		return file_path

	def read_file(self, file_path):
		with open(file_path, 'r') as f:
			for line in f:
				yield line.strip()

	def fetch_proxy(self):
		
		try:
			headers = {
				"Content-type" : "application/json",
				"Accept" : "application/json"
			}
			api_url = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=us&protocol=http,socks4&proxy_format=ipport&format=json&timeout=10000"
			response = requests.get(api_url, headers)
			response.raise_for_status()
			proxies = response.json()['proxies']
				
			return [Proxy(proxy['ip'], proxy['port'], proxy['protocol']) for proxy in proxies]
		except Exception as e:
			print(f"Failed to get proxies: {e}")
			return None


	def find_valid_proxy(self, host, port, proxies):
		current_count = 0
		current_proxy = Proxy("0.0.0.0", int(80), "http")
		
		for idx, proxy in enumerate(proxies, start=1):
			try:
				current_count = idx
				current_proxy = proxy
				status = self.check_smtp_port(host, port, proxy)
				print(f"\rTrying proxy ({current_proxy.protocol}): {current_proxy.host}:{current_proxy.port}:- {idx}/{len(proxies)} | ({int((current_count / len(proxies)) * 100)}%)\033[K", end="")
				
				if status == True:
					print(f"Proxy found: {proxy.host}:{proxy.port} - with protocol: {proxy.protocol}")
					return proxy
			except Exception as e:
				# print(f"Failed to connect to port {host}:{port} with proxy {proxy.host}:{proxy.port} - {e}")
				continue

		return None

	def check_smtp_port(self, host, port, proxy):
		try:
			match proxy.protocol:
				case 'socks4':
					socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
				case 'socks5':
					socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
				case 'http':
					socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)

			# socks.set_default_proxy(proxy['type'], proxy['host'], proxy['port'])
			socks.wrapmodule(smtplib)
			with smtplib.SMTP_SSL(host, port, timeout=6) as server:
				server.ehlo(f"{host}")
				server.starttls()
				server.ehlo(f"{host}")
				server.noop()  # Test connection
				return True
			return False

		except (socket.error, smtplib.SMTPException) as e:
			# print(f'Mail Exchange Connection failed {e}')
			return False

	def test_smtp_login(self, smtp_host, smtp_port, username, password, proxy, protocol):
		server = MX_Server(smtp_host, smtp_port)
		try:
			match protocol:
				case "ssl":
					connection = connect_ssl(server, proxy)
				case "tls":
					connection = connect_tls(host, port, proxy)
			if connection is None:
				print(f"Unable to establish SMTP connection: {smtp_host}:{smtp_port} - protocol: {protocol}")
				return False
			else:
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
						print(f"Server Error: {response}")
						return False

				connection.sendall("QUIT\r\n".encode())
				return True

		except Exception as e:
			print(f'Mail Exchange Connection failed {e}')
			return False

	def group_by_domain(self, emails):
		grouped_emails = defaultdict(list)
		for email in emails:
			if re.match(r"[^@]+@[^@]+\.[^@]+", email) and filter_spam(email.split('@')[0].strip()):
				domain = email.split('@')[1].strip().lower()
				if not is_banned_tld(domain):
					grouped_emails[domain].append(email)

		valid_email_groups = {}

		for domain, domain_emails in grouped_emails.items():
			if domain not in blocklist:
				valid_email_groups[domain] = domain_emails

		return valid_email_groups

		
	def is_banned_tld(self, domain):
		banned_tlds = [".xyz", ".top", ".info", ".buzz", ".click", ".online", ".bank", ".finance", ".us", ".gov", ".gov.ng", ".gov.us"]
		if any(domain.endswith(tld) for tld in banned_tlds):
			return True
		return any(domain.endswith(tld) for tld in banned_tlds)

	def filter_spam(self, email):
		spam_words = [
			"free", "win", "cash", "offer", 
			"prize", "winner", "lottery", 
			"urgent", "info", "contact", 
			"security", "sales", 
			"abuse", "complaints", 
			"webmaster", "report",
		]
		for word in spam_words:
			if word in email.lower():
				return False
		return True

	def get_mx_servers(self, domain):
		try:
			if domain == 'outlook.com':
				return ['smtp-mail.outlook.com']
			else:
				mx_records = dns.resolver.resolve(domain, 'MX')
				mx_record = sorted(mx_records, key=lambda r: r.preference)[0]
				return str(mx_record.exchange).rstrip('.')
		except Exception as e:
			return None

	def connect_ssl(self, mx_server, proxy):

		return None

	def connect_tls(self, host, port, proxy):

		return None
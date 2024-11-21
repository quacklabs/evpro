class Proxy:

    def __init__(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol

    def __repr__(self):
        return f"Proxy(host={self.host}, port={self.port}, protocol={self.protocol})"

class MX_Server:

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __repr__(self):
        return f"MX_Server(host={self.host}, port={self.port})"

class Credentials:

    def __init__(self, host, port, username, password, domain):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = True
        self.domain = domain


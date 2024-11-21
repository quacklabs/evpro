from abc import ABC, abstractmethod
from servers import MX_Server

# Interface for Validate Mode
class Validate(ABC):
    @property
    @abstractmethod
    def sample_size(self):
        pass


# Interface for Send Mode
class Send(ABC):
    @property
    @abstractmethod
    def sender(self):
        pass

    @property
    @abstractmethod
    def content(self):
        pass

    @property
    @abstractmethod
    def subject(self):
        pass


class Base(ABC):
    def __init__(self, mx_server: str, mode: str):
        self.mx_server = mx_server
        if mode not in ['validate', 'send']:
            raise ValueError("Mode must be 'validate' or 'send'")
        self.mode = mode

    @abstractmethod
    def operate(self):
        pass

class Validator(Base, Validate):
    def __init__(self, mx_server: MX_Server, sample_size: int):
        super().__init__(mx_server, 'validate')
        self._sample_size = sample_size

    @property
    def sample_size(self):
        return self._sample_size

    def operate(self):
        return f"Validating with sample size {self.sample_size} on MX server {self.mx_server}"

class Sender(Base, Send):
    def __init__(self, mx_server: str, sender: str, content: str, subject: str):
        super().__init__(mx_server, 'send')
        self._sender = sender
        self._content = content
        self._subject = subject

    @property
    def sender(self):
        return self._sender

    @property
    def content(self):
        return self._content

    @property
    def subject(self):
        return self._subject

    def operate(self):
        return f"Sending email from {self.sender} with subject '{self.subject}' and content '{self.content}' on MX server {self.mx_server}"

import socket
from pydantic import BaseModel, model_validator

class Settings(BaseModel):
    host_ip: str | None = None
    port: int = 8500
    ssl_keyfile: str = "key.pem"
    ssl_certfile: str = "cert.pem"
    blue_color: str = "#0000ff"

    @model_validator(mode='after')
    def set_host_ip(self):
        if not self.host_ip:
            self.host_ip = self._get_local_ip()
        return self

    def _get_local_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

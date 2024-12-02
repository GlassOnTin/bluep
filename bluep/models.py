from datetime import datetime
from pydantic import BaseModel
from typing import Optional, Literal

class SessionData(BaseModel):
    username: str
    expiry: datetime
    last_totp_use: str  # Store last used TOTP code to prevent replay attacks

class WebSocketMessage(BaseModel):
    type: Literal["content", "cursor"]
    data: Optional[str] = None
    x: Optional[int] = None
    y: Optional[int] = None
    clientId: Optional[int] = None

    @classmethod
    def model_validate_message(cls, data: str):
        return cls.model_validate_json(data)

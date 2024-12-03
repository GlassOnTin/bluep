from typing import Any, Optional, Union
from PIL.Image import Image

class QRCode:
    def __init__(
        self,
        version: Optional[int] = None,
        box_size: int = 10,
        border: int = 4,
    ) -> None: ...
    def add_data(self, data: str) -> None: ...
    def make(self, fit: bool = True) -> None: ...
    def make_image(
        self, fill_color: str = "black", back_color: str = "white"
    ) -> Image: ...

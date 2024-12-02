# bluep

A minimal real-time collaborative text editor with a blue theme. Multiple users can connect and edit text simultaneously through their browsers.

## Features
- Real-time text synchronization across all connected clients
- WebSocket-based communication
- HTTPS support
- Minimalist blue interface
- Automatic local IP detection

## Installation

```bash
git clone https://github.com/glassontin/bluep.git
cd bluep
pip install fastapi uvicorn pillow
```

## SSL Certificate Setup
Generate self-signed certificates for HTTPS:
```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
```

## Usage
1. Run the server:
```bash
python bluep/bluep.py
```

2. Open your browser and navigate to:
```
https://<your-local-ip>:8500
```

## Dependencies
- FastAPI
- uvicorn
- Pillow
- Python 3.7+

## License
MIT License

Copyright (c) 2024 glassontin

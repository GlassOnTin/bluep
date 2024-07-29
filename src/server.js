const express = require('express');
const app = express();
const https = require('https')
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8500;

// SSL/TLS certificate and key
const options = {
  key: fs.readFileSync('certs/key.pem'),
  cert: fs.readFileSync('certs/cert.pem')
};

// Create an HTTPS server
const server = https.createServer(options, app);

// Initialize the Socket.IO server with increased maxHttpBufferSize
const io = require('socket.io')(server, {
  maxHttpBufferSize: 1e8 // 100 MB
});

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, '../public')));

// Serve the index.html file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Attach Socket.IO to the HTTPS server
io.attach(server);

// Store the clipboard content
let clipboardContent = '';

// Handle Socket.IO connections
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  // Send the current clipboard content to the new client
  socket.emit('clipboardContent', clipboardContent);

  // Receive clipboard content updates from clients
  socket.on('updateClipboard', (data) => {
    clipboardContent = data;
    // Broadcast the updated clipboard content to all connected clients
    io.emit('clipboardContent', clipboardContent);
  });

  // Receive file data from clients
  socket.on('fileData', (data) => {
    console.log('Received file data:', data);
    io.emit('fileData', data);
    console.log('Broadcasted fileData event');
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});

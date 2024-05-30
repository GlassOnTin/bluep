const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http);

const PORT = process.env.PORT || 8080;

// Store the clipboard content
let clipboardContent = '';

// Serve the index.html file
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Handle Socket.IO connections
io.on('connection', (socket) => {
  console.log('A user connected');

  // Send the current clipboard content to the new client
  socket.emit('clipboardContent', clipboardContent);

  // Receive clipboard content updates from clients
  socket.on('updateClipboard', (data) => {
    clipboardContent = data;
    // Broadcast the updated clipboard content to all connected clients
    io.emit('clipboardContent', clipboardContent);
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});

http.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
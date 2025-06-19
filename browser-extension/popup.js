// Popup script for Bluep MCP Bridge extension

document.addEventListener('DOMContentLoaded', () => {
  const statusEl = document.getElementById('status');
  const startBtn = document.getElementById('start-server');
  const stopBtn = document.getElementById('stop-server');
  
  // Check current status
  chrome.storage.local.get(['serverRunning'], (result) => {
    updateUI(result.serverRunning || false);
  });
  
  // Start server
  startBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'start-proxy' }, (response) => {
      if (response && response.success) {
        updateUI(true);
      }
    });
  });
  
  // Stop server
  stopBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'stop-proxy' }, (response) => {
      if (response && response.success) {
        updateUI(false);
      }
    });
  });
  
  // Listen for status updates
  chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.serverRunning) {
      updateUI(changes.serverRunning.newValue);
    }
  });
  
  function updateUI(serverRunning) {
    if (serverRunning) {
      statusEl.textContent = 'Local server running on port 4000';
      statusEl.className = 'status connected';
      startBtn.disabled = true;
      stopBtn.disabled = false;
    } else {
      statusEl.textContent = 'Native helper not connected';
      statusEl.className = 'status disconnected';
      startBtn.disabled = false;
      stopBtn.disabled = true;
    }
  }
});
// Background service worker for Bluep MCP Bridge extension

let localServer = null;
let activeConnections = new Map();

// Start local HTTP server on port 4000
async function startLocalServer() {
  // Use Chrome's native messaging to communicate with a local helper app
  // The helper app would create the actual HTTP server
  
  try {
    const port = chrome.runtime.connectNative('com.bluep.mcp_bridge');
    
    port.onMessage.addListener((msg) => {
      if (msg.type === 'server-started') {
        console.log('Local MCP bridge server started on port 4000');
        chrome.storage.local.set({ serverRunning: true });
      } else if (msg.type === 'request') {
        // Forward to bluep via content script
        forwardToBluep(msg);
      }
    });
    
    port.onDisconnect.addListener(() => {
      console.log('Native helper disconnected');
      chrome.storage.local.set({ serverRunning: false });
    });
    
    // Start the server
    port.postMessage({ action: 'start-server', port: 4000 });
    localServer = port;
    
  } catch (error) {
    console.error('Failed to start native helper:', error);
  }
}

// Forward MCP request to bluep
async function forwardToBluep(request) {
  // Send to active tab running bluep
  const tabs = await chrome.tabs.query({ url: 'https://*/mcp*' });
  if (tabs.length > 0) {
    chrome.tabs.sendMessage(tabs[0].id, {
      type: 'mcp-request',
      payload: request.payload,
      requestId: request.id
    });
  }
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'start-proxy') {
    startLocalServer();
    sendResponse({ success: true });
  } else if (request.type === 'stop-proxy') {
    if (localServer) {
      localServer.postMessage({ action: 'stop-server' });
      localServer.disconnect();
      localServer = null;
    }
    sendResponse({ success: true });
  } else if (request.type === 'mcp-response') {
    // Forward response back to local server
    if (localServer) {
      localServer.postMessage({
        type: 'response',
        requestId: request.requestId,
        payload: request.payload
      });
    }
  }
  return true; // Keep message channel open for async response
});

// Initialize
chrome.storage.local.set({ serverRunning: false });
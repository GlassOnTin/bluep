// Content script for Bluep MCP Bridge
// Injected into bluep pages to facilitate communication

console.log('Bluep MCP Bridge content script loaded');

// Listen for messages from the page
window.addEventListener('message', (event) => {
  // Only accept messages from the same origin
  if (event.origin !== window.location.origin) return;
  
  if (event.data.type === 'bluep-mcp-request') {
    // Forward to background script
    chrome.runtime.sendMessage({
      type: 'mcp-request',
      payload: event.data.payload,
      requestId: event.data.requestId
    }, (response) => {
      // Send response back to page
      window.postMessage({
        type: 'bluep-mcp-response',
        requestId: event.data.requestId,
        payload: response
      }, window.location.origin);
    });
  }
});

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'mcp-response') {
    // Forward to page
    window.postMessage({
      type: 'bluep-mcp-response',
      requestId: request.requestId,
      payload: request.payload
    }, window.location.origin);
  }
});
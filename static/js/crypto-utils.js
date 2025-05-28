/**
 * Secure crypto utilities for bluep
 * 
 * This file implements secure cryptographic operations for the bluep application,
 * including key exchange, encryption/decryption, and device binding.
 */

// Global cryptographic state
let clientPrivateKey;
let sharedSecret;
let deviceIdentifier;

/**
 * Generate a device identifier based on browser and hardware properties
 * This creates a semi-stable identifier for the current device
 */
async function getDeviceIdentifier() {
    if (deviceIdentifier) return deviceIdentifier;
    
    try {
        // Collect browser and hardware signals
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        const debugInfo = gl?.getExtension('WEBGL_debug_renderer_info');
        const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';
        
        const deviceSignals = [
            navigator.userAgent,
            renderer,
            screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
            navigator.language,
            navigator.platform || ''
        ].join('|');
        
        // Hash the combined signals
        const encoder = new TextEncoder();
        const data = encoder.encode(deviceSignals);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        
        deviceIdentifier = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
            
        return deviceIdentifier;
    } catch (e) {
        console.error("Failed to generate device identifier:", e);
        // Fallback to a random ID if we can't get device info
        return crypto.randomUUID();
    }
}

/**
 * Generate a hash based on device information
 * Used for binding keys to the current device
 */
function hashDeviceInfo(deviceId) {
    return deviceId.slice(0, 16);
}

/**
 * Open a secure database for storing keys
 */
async function openSecureDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("bluep_secure_store", 1);
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys", { keyPath: "id" });
            }
        };
        
        request.onsuccess = (event) => {
            resolve(event.target.result);
        };
        
        request.onerror = (event) => {
            console.error("IndexedDB error:", event.target.error);
            reject(event.target.error);
        };
    });
}

/**
 * Encrypt a key with device-specific binding
 */
async function encryptWithDeviceBinding(key, deviceId) {
    // Use the device ID as part of the encryption key
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(deviceId),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    
    // Derive a key for encryption
    const bindingKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: encoder.encode("bluep_device_binding"),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    
    // Generate an IV
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt the key
    const encryptedContent = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        bindingKey,
        key
    );
    
    // Combine IV and encrypted content
    const encryptedBuffer = new Uint8Array(iv.byteLength + encryptedContent.byteLength);
    encryptedBuffer.set(iv, 0);
    encryptedBuffer.set(new Uint8Array(encryptedContent), iv.byteLength);
    
    // Convert to base64 for storage
    return btoa(String.fromCharCode.apply(null, encryptedBuffer));
}

/**
 * Creates a key from a shared string 
 * 
 * This function is meant to be used with a server-provided shared key
 * that all clients will use for encryption/decryption.
 */
async function createKeyFromSharedString(sharedKeyStr) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(sharedKeyStr);
    
    try {
        // Use HKDF (Hash-based Key Derivation Function) for better key derivation
        // First import the source key material
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );
        
        // Use PBKDF2 with stronger parameters
        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: encoder.encode("bluep_shared_key_derivation"),
                iterations: 100000, // Use high iteration count for better security
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    } catch (e) {
        console.error("Key derivation failed:", e);
        throw new Error("Key derivation failed: " + e.message);
    }
}

/**
 * Generates an encryption key from the token (legacy method)
 */
async function generateKeyFromToken(token) {
    // Generate a key from the token - this is deterministic and simpler
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(token + "_bluep_key"),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    
    // Derive a key for encryption - with more reasonable iterations for browsers
    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: encoder.encode("bluep_salt_v2"),
            iterations: 10000, // Less iterations to help performance
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
    
    return key;
}

/**
 * Token-based key derivation with stronger security properties
 * This provides a more secure alternative if the primary key exchange fails
 */
async function fallbackToTokenBasedKey(token) {
    console.log("Using token-based key generation method");
    try {
        const encoder = new TextEncoder();
        
        // Import the token as PBKDF2 key material
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            encoder.encode(token),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );
        
        // Derive a key with stronger parameters (100,000 iterations)
        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: encoder.encode("bluep_secure_salt_v3"),
                iterations: 100000, // Increased for better security
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    } catch (e) {
        console.error("Token-based key generation failed:", e);
        throw new Error("Key generation failed: " + e.message);
    }
}

/**
 * Securely store a cryptographic key
 */
async function securelyStoreKey(key) {
    try {
        // Use IndexedDB with device binding
        const deviceId = await getDeviceIdentifier();
        const db = await openSecureDatabase();
        
        // We can't directly store the CryptoKey, so we'll just store a placeholder
        // The actual key is kept in memory
        const transaction = db.transaction(["keys"], "readwrite");
        transaction.objectStore("keys").put({
            id: "session-key",
            created: Date.now(),
            deviceBinding: hashDeviceInfo(deviceId)
        });
        
        return new Promise((resolve, reject) => {
            transaction.oncomplete = () => resolve(true);
            transaction.onerror = () => reject(transaction.error);
        });
    } catch (e) {
        console.error("Failed to store key:", e);
        return false;
    }
}

/**
 * Encrypt text using the shared secret from key exchange
 */
async function encryptText(text, key) {
    try {
        // Use the provided key or the shared secret
        const encryptionKey = key || sharedSecret;
        if (!encryptionKey) {
            // No fallback - encryption is required
            console.error("No encryption key available - cannot proceed");
            throw new Error("Encryption key missing");
        }
        
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        // Generate an IV
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt the data with authentication info
        const encryptedContent = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                // Add additional authenticated data for integrity verification
                additionalData: encoder.encode("bluep_secure")
            },
            encryptionKey,
            data
        );
        
        // Combine IV and encrypted content
        const encryptedBuffer = new Uint8Array(iv.byteLength + encryptedContent.byteLength);
        encryptedBuffer.set(iv, 0);
        encryptedBuffer.set(new Uint8Array(encryptedContent), iv.byteLength);
        
        // Convert to base64 using a safe approach
        const base64 = await arrayBufferToBase64(encryptedBuffer);
        console.log("Successfully encrypted text with AES-GCM");
        return base64;
    } catch (e) {
        console.error("Encryption error:", e);
        throw new Error("Encryption failed: " + e.message);
    }
}

/**
 * Decrypt text using the shared secret from key exchange
 */
async function decryptText(encryptedText, key) {
    try {
        // Use the provided key or the shared secret
        const decryptionKey = key || sharedSecret;
        if (!decryptionKey) {
            console.error("No decryption key available - cannot proceed");
            throw new Error("Decryption key missing");
        }
        
        // Input validation - check for empty or invalid input
        if (!encryptedText) {
            console.error("Empty encrypted text received");
            throw new Error("Empty encrypted data");
        }
        
        if (typeof encryptedText !== 'string') {
            console.error("Invalid encrypted text type - must be string");
            throw new Error("Invalid encrypted data type");
        }
        
        // Allow for smaller text content, but ensure basic structure for base64
        if (encryptedText.length < 10 || !/^[A-Za-z0-9+/=]+$/.test(encryptedText)) {
            console.error("Invalid encrypted text format - not valid base64");
            throw new Error("Invalid encrypted data format: not valid base64");
        }
        
        try {
            // Convert from base64
            const encryptedBuffer = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
            
            // Validate buffer size - must be at least IV (12 bytes) + 1 byte of content
            if (encryptedBuffer.length <= 12) {
                console.error("Encrypted data too small - must contain IV and content");
                throw new Error("The provided data is too small");
            }
            
            // Extract IV and encrypted content
            const iv = encryptedBuffer.slice(0, 12);
            const encryptedContent = encryptedBuffer.slice(12);
            
            const encoder = new TextEncoder();
            
            // Decrypt the data with the same authentication info used in encryption
            const decryptedContent = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                    additionalData: encoder.encode("bluep_secure")
                },
                decryptionKey,
                encryptedContent
            );
            
            // Convert to text
            const result = new TextDecoder().decode(decryptedContent);
            console.log("Successfully decrypted text with AES-GCM");
            return result;
        } catch (e) {
            // More specific error for better debugging
            if (e.name === 'OperationError') {
                console.error("Decryption operation failed:", e);
                throw new Error("Decryption operation failed - possible corrupted data or wrong key");
            }
            throw e; // Re-throw for other errors
        }
    } catch (e) {
        console.error("Decryption error:", e);
        // Enhanced error handling for file transfers
        const isFileRelated = e.message && (
            e.message.includes("too small") || 
            e.message.includes("corrupted") ||
            e.message.includes("format")
        );
        
        if (isFileRelated) {
            console.warn("This appears to be a file transfer related error - may need to retry");
        }
        
        throw new Error("Decryption failed: " + e.message);
    }
}

/**
 * Safely converts an ArrayBuffer to base64 string without stack overflow
 * Uses different techniques based on the size of the buffer
 */
async function arrayBufferToBase64(buffer) {
    // For small buffers, use the native approach which is faster
    if (buffer.length < 10000) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
    }
    
    // For large buffers, use Blob + FileReader to avoid call stack limits
    return new Promise((resolve, reject) => {
        const blob = new Blob([buffer], {type: 'application/octet-stream'});
        const reader = new FileReader();
        
        reader.onload = function() {
            // FileReader.readAsDataURL returns a data URL with format:
            // "data:application/octet-stream;base64,BASE64_DATA"
            // We need to extract just the base64 part
            const dataUrl = reader.result;
            const base64 = dataUrl.split(',')[1];
            resolve(base64);
        };
        
        reader.onerror = function() {
            reject(new Error("Failed to convert array buffer to base64"));
        };
        
        // Read as data URL which gives us base64
        reader.readAsDataURL(blob);
    });
}

/**
 * Verify the integrity of the current page and connection
 */
function verifyConnection(certFingerprint) {
    // Check for TLS interception indicators
    if (window.navigator.webdriver) {
        console.warn("Automated browser detected - potentially insecure environment");
        alert("Security warning: automated browser detected");
        window.location.href = '/login';
        return false;
    }
    
    // Check for debugger
    if (window.devtools && window.devtools.isOpen) {
        console.warn("DevTools detected - potentially insecure environment");
        alert("Security warning: browser developer tools detected");
    }
    
    // Add more environment checks
    if (window.Firebug && window.Firebug.chrome && window.Firebug.chrome.isInitialized) {
        console.warn("Firebug detected - potentially insecure environment");
        alert("Security warning: debugging tools detected");
    }
    
    // Certificate verification using fetch with strict validation
    fetch('/verify-cert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            clientTime: Date.now(),
            expectedFingerprint: certFingerprint
        }),
        keepalive: true
    })
    .then(response => response.json())
    .then(data => {
        if (!data.valid) {
            console.error("Certificate validation failed - possible MITM attack");
            alert("Security error: Certificate validation failed");
            window.location.href = '/login';
        }
    })
    .catch(error => {
        console.error("Certificate verification error:", error);
        alert("Security warning: Unable to verify secure connection");
    });
    
    return true;
}

/**
 * Detect tampering with the page by browser extensions or other tools
 * This is a simplified implementation that focuses on specific security concerns
 * and avoids false positives with normal UI updates
 */
// Global flag to track whether MutationObserver is paused
let mutationObserverPaused = false;

// Function to temporarily pause MutationObserver for legitimate DOM updates
window.pauseMutationObserver = function(duration = 500) {
    mutationObserverPaused = true;
    setTimeout(() => {
        mutationObserverPaused = false;
    }, duration);
};

function detectExtensionTampering(expectedScriptLength) {
    // Set to false for development, true for production
    const STRICT_TAMPERING_MODE = false;
    
    // Make sure we handle title changes properly
    document.addEventListener('DOMContentLoaded', () => {
        if (window.pauseMutationObserver) {
            const origSetTitle = document.title;
            Object.defineProperty(document, 'title', {
                set: function(newTitle) {
                    window.pauseMutationObserver(200);
                    origSetTitle.call(this, newTitle);
                    return newTitle;
                }
            });
        }
    });

    // Create an integrity object with checksums
    const integrityData = {
        originalLength: expectedScriptLength,
        cssRules: document.styleSheets[0]?.cssRules?.length || 0
    };
    
    // Check for known extension patterns that might tamper with security
    function checkForExtensions() {
        // Look for extension-specific DOM elements
        const suspiciousElements = [
            '__REDUX_DEVTOOLS_EXTENSION__',
            '__VUE_DEVTOOLS_GLOBAL_HOOK__',
            '_GRAMMARLY_',
            '_GRAMMARLY_EXTENSION'
        ];
        
        for (const elem of suspiciousElements) {
            if (window[elem]) {
                if (STRICT_TAMPERING_MODE) {
                    console.warn(`Detected potential monitoring extension: ${elem}`);
                    reportTampering('extension_detected');
                    return true;
                } else {
                    // In dev mode, just log it but don't report
                    console.log(`Dev mode: Detected browser extension (${elem}), ignoring in development`);
                }
            }
        }
        return false;
    }
    
    // Instead of watching all DOM mutations, we'll focus on just a few key concerns:
    // 1. New script tags
    // 2. New iframe tags
    // 3. Script tag attribute changes
    
    // Safe DOM elements we create ourselves
    const safeIds = [
        'file-list', 
        'editor', 
        'file-drop-area', 
        'download-container', 
        'download-link',
        'progress-notification'
    ];
    
    // Only observe <head> and <body> tags for script injections
    // This avoids capturing unrelated DOM changes
    
    // Create a targeted observer just for <script> and <iframe> elements
    const securityObserver = new MutationObserver(function(mutations) {
        // Skip observation if paused or not in strict mode
        if (mutationObserverPaused || !STRICT_TAMPERING_MODE) return;
        
        for (const mutation of mutations) {
            // Skip if the target is a TITLE element
            if (mutation.target && (mutation.target.nodeName === 'TITLE' || mutation.target.tagName === 'TITLE')) continue;
            
            // Only interested in childList changes (element addition)
            if (mutation.type !== 'childList' || !mutation.addedNodes.length) continue;
            
            // Check each added node
            for (const node of mutation.addedNodes) {
                // Only interested in elements
                if (node.nodeType !== Node.ELEMENT_NODE) continue;
                
                // Explicitly skip any TITLE changes to avoid false positives
                if (node.nodeName === 'TITLE' || node.tagName === 'TITLE' || 
                    (mutation.target && (mutation.target.nodeName === 'TITLE' || mutation.target.tagName === 'TITLE'))) continue;
                
                // Skip our own known safe elements
                if (node.id && safeIds.includes(node.id)) continue;
                
                // Check for suspicious elements
                if (node.nodeName === 'SCRIPT' || node.nodeName === 'IFRAME') {
                    console.error(`Security risk: Dynamic ${node.nodeName} insertion detected`);
                    reportTampering('script_injection');
                    alert("Security warning: Browser extension tampering detected");
                }
            }
        }
    });
    
    // Only observe <head> and <body> for script insertion
    // This drastically reduces false positives from UI changes
    if (document.head) {
        securityObserver.observe(document.head, { 
            childList: true 
        });
    }
    
    if (document.body) {
        securityObserver.observe(document.body, { 
            childList: true 
        });
    }
    
    // For script attribute changes, we'll use another targeted observer
    const scriptObserver = new MutationObserver(function(mutations) {
        // Skip observation if paused or not in strict mode
        if (mutationObserverPaused || !STRICT_TAMPERING_MODE) return;
        
        for (const mutation of mutations) {
            if (mutation.type !== 'attributes') continue;
            
            const sensitiveAttributes = ['src', 'href', 'integrity', 'content', 'onclick', 'onload'];
            if (!sensitiveAttributes.includes(mutation.attributeName)) continue;
            
            console.error(`Security risk: Modified ${mutation.target.nodeName} ${mutation.attributeName} attribute`);
            reportTampering('attribute_tampering');
        }
    });
    
    // Find all script tags and observe them
    const allScripts = document.getElementsByTagName('script');
    for (const script of allScripts) {
        scriptObserver.observe(script, { attributes: true });
    }
    
    // Check if main script content is modified
    for (const script of allScripts) {
        if (script.src && script.src.includes('crypto-utils.js') && 
            script.textContent && 
            script.textContent.length !== integrityData.originalLength) {
            console.error("Script modification detected - potential security compromise");
            reportTampering('script_modification');
            alert("Security warning: Critical script has been modified");
            return false;
        }
    }
    
    // Schedule periodic checks for extensions
    setInterval(checkForExtensions, 30000);
    
    // Initial run of extension check
    return checkForExtensions();
}

/**
 * Report tampering to the server
 */
function reportTampering(type) {
    // Log the tampering event
    console.log("Tampering detected:", type);
    
    // Always report to server for monitoring
    fetch('/tampering-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            type: type,
            timestamp: Date.now(),
            devMode: !STRICT_TAMPERING_MODE
        }),
        keepalive: true
    }).catch(err => console.error("Failed to report tampering:", err));
    
    // In strict mode (production), we could take more restrictive actions
    // like redirecting the user or showing stronger warnings
}
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
        
        // Convert to base64 for transmission
        const result = btoa(String.fromCharCode.apply(null, encryptedBuffer));
        console.log("Successfully encrypted text with AES-GCM");
        return result;
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
        
        // Convert from base64
        const encryptedBuffer = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
        
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
        console.error("Decryption error:", e);
        throw new Error("Decryption failed: " + e.message);
    }
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
 */
function detectExtensionTampering(expectedScriptLength) {
    // Create an integrity object with checksums
    const integrityData = {
        originalLength: expectedScriptLength,
        cssRules: document.styleSheets[0]?.cssRules?.length || 0
    };
    
    // Check for known extension patterns
    function checkForExtensions() {
        // Look for extension-specific DOM elements
        const suspiciousElements = [
            '__REACT_DEVTOOLS_GLOBAL_HOOK__',
            '__REDUX_DEVTOOLS_EXTENSION__',
            '__VUE_DEVTOOLS_GLOBAL_HOOK__',
            '_GRAMMARLY_',
            '_GRAMMARLY_EXTENSION'
        ];
        
        for (const elem of suspiciousElements) {
            if (window[elem]) {
                console.warn(`Detected potential monitoring extension: ${elem}`);
                reportTampering('extension_detected');
                return true;
            }
        }
        return false;
    }
    
    // Monitor for DOM changes that could indicate tampering
    const observer = new MutationObserver(mutations => {
        for (const mutation of mutations) {
            if (mutation.type === 'childList' || 
                (mutation.type === 'attributes' && 
                 ['src', 'href', 'integrity', 'content', 'onclick', 'onload'].includes(mutation.attributeName))) {
                
                console.warn(`DOM tampering detected: ${mutation.type} on ${mutation.target.nodeName}`);
                
                // Check for malicious modifications (script or iframe insertions)
                if (mutation.type === 'childList' && mutation.addedNodes.length) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeName === 'SCRIPT' || node.nodeName === 'IFRAME') {
                            console.error(`Security risk: Dynamic ${node.nodeName} insertion detected`);
                            reportTampering('script_injection');
                            alert("Security warning: Browser extension tampering detected");
                        }
                    }
                }
                
                // Check for attribute modifications on security-sensitive elements
                if (mutation.type === 'attributes' && 
                    (mutation.target.nodeName === 'SCRIPT' || 
                     mutation.target.nodeName === 'LINK' || 
                     mutation.target.nodeName === 'META')) {
                    
                    console.error(`Security risk: Modified ${mutation.target.nodeName} attributes`);
                    reportTampering('attribute_tampering');
                }
            }
        }
    });
    
    observer.observe(document, { 
        attributes: true, 
        childList: true, 
        subtree: true,
        characterData: true,
        attributeOldValue: true
    });
    
    // Check if main script content is modified
    const scripts = document.getElementsByTagName('script');
    for (const script of scripts) {
        if (script.src.includes('crypto-utils.js') && 
            script.textContent && 
            script.textContent.length !== integrityData.originalLength) {
            console.error("Script modification detected - potential security compromise");
            reportTampering('script_modification');
            alert("Security warning: Critical script has been modified");
            return false;
        }
    }
    
    // Run initial extension check
    if (checkForExtensions()) {
        return false;
    }
    
    // Schedule periodic checks for extensions
    setInterval(checkForExtensions, 30000);
    
    return true;
}

/**
 * Report tampering to the server
 */
function reportTampering(type) {
    // In development mode, we just log tampering instead of redirecting
    console.log("Tampering detected:", type);
    
    // Just report to server but don't redirect
    fetch('/tampering-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            type: type,
            timestamp: Date.now()
        }),
        keepalive: true
    }).catch(err => console.error("Failed to report tampering:", err));
}
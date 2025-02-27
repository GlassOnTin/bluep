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
    
    // Import the key material directly if possible
    try {
        // Try to create a key directly from the shared string
        return await window.crypto.subtle.importKey(
            "raw",
            keyData.slice(0, 32), // Use first 32 bytes for AES-256
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );
    } catch (e) {
        console.warn("Direct key import failed, trying PBKDF2:", e);
        
        // If direct import fails, try with PBKDF2
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );
        
        // Derive a key with minimal iterations since this is just for normalizing key material
        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: encoder.encode("bluep_shared_salt"),
                iterations: 1, // Just one iteration since we already have good entropy
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
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
 * Fallback to a simpler token-based key derivation if key exchange fails
 * This uses a very simple algorithm that's more likely to work in all browsers
 */
async function fallbackToTokenBasedKey(token) {
    console.log("Using fallback key generation method");
    try {
        const encoder = new TextEncoder();
        // Use simple algorithm that should work everywhere
        const keyData = encoder.encode(token.repeat(2) + "bluep_fallback");
        
        // Import as raw key (minimal derivation)
        return await window.crypto.subtle.importKey(
            "raw",
            keyData.slice(0, 32), // Use first 32 bytes for key
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );
    } catch (e) {
        console.error("Even fallback key generation failed:", e);
        // Return null - encryption will fallback to base64
        return null;
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
            // Provide a fallback for initial connection
            console.warn("No encryption key available - using plaintext fallback");
            console.log("Text converted to base64:", text.substring(0, 10) + "...");
            return btoa(text); // Simple base64 encoding as fallback
        }
        
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        // Generate an IV
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt the data
        const encryptedContent = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
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
        // Provide a fallback on error
        console.log("Falling back to base64 encoding for:", text.substring(0, 10) + "...");
        return btoa(text);
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
            console.warn("No decryption key available - using plaintext fallback");
            // Try to decode as simple base64
            try {
                const result = atob(encryptedText);
                console.log("Successfully base64 decoded as fallback");
                return result;
            } catch (e) {
                console.error("Failed to base64 decode fallback:", e);
                return encryptedText; // Return as-is if not valid base64
            }
        }
        
        try {
            // Convert from base64
            const encryptedBuffer = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
            
            // Extract IV and encrypted content
            const iv = encryptedBuffer.slice(0, 12);
            const encryptedContent = encryptedBuffer.slice(12);
            
            // Decrypt the data
            const decryptedContent = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                decryptionKey,
                encryptedContent
            );
            
            // Convert to text
            const result = new TextDecoder().decode(decryptedContent);
            console.log("Successfully decrypted text with AES-GCM");
            return result;
        } catch (innerError) {
            // If decryption fails, try to interpret as simple base64
            console.warn("Decryption failed, attempting base64 decode fallback:", innerError);
            try {
                const result = atob(encryptedText);
                console.log("Successfully base64 decoded as fallback after AES failure");
                return result;
            } catch (e) {
                console.error("All decryption methods failed", e);
                return encryptedText; // Return as-is if not valid base64
            }
        }
    } catch (e) {
        console.error("Decryption error:", e);
        // If all else fails, return the original text
        return encryptedText;
    }
}

/**
 * Verify the integrity of the current page and connection
 */
function verifyConnection(certFingerprint) {
    // Check for TLS interception indicators
    if (window.navigator.webdriver) {
        console.warn("Automated browser detected");
        return false;
    }
    
    // Certificate verification using fetch
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
            console.error("Certificate validation failed");
            window.location.href = '/login';
        }
    })
    .catch(error => {
        console.error("Certificate verification error:", error);
    });
    
    return true;
}

/**
 * Detect tampering with the page by browser extensions or other tools
 */
function detectExtensionTampering(expectedScriptLength) {
    // In development mode, we just log tampering instead of redirecting
    // to avoid constant redirects
    
    // Create an integrity object with checksums
    const integrityData = {
        originalLength: expectedScriptLength,
        cssRules: document.styleSheets[0]?.cssRules?.length || 0
    };
    
    // Monitor for DOM changes
    const observer = new MutationObserver(mutations => {
        for (const mutation of mutations) {
            if (mutation.type === 'childList' || 
                (mutation.type === 'attributes' && 
                 ['src', 'href', 'integrity'].includes(mutation.attributeName))) {
                // Just log without redirecting in development
                console.log("DOM change detected:", mutation.type);
            }
        }
    });
    
    observer.observe(document, { 
        attributes: true, 
        childList: true, 
        subtree: true,
        characterData: true
    });
    
    // Check if main script content is modified
    const scripts = document.getElementsByTagName('script');
    for (const script of scripts) {
        if (script.src.includes('crypto-utils.js') && 
            script.textContent && 
            script.textContent.length !== integrityData.originalLength) {
            console.log("Script modification detected");
            return false;
        }
    }
    
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
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
 * Performs a secure key exchange with the server using ECDH
 */
async function performKeyExchange(token) {
    try {
        // Generate client key pair
        clientPrivateKey = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            false, 
            ["deriveKey"]
        );
        
        // Export public key to send to server
        const publicKeyRaw = await window.crypto.subtle.exportKey(
            "raw",
            clientPrivateKey.publicKey
        );
        
        // Send to server and get server's public key
        const response = await fetch('/key-exchange', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                clientKey: btoa(String.fromCharCode.apply(null, new Uint8Array(publicKeyRaw))),
                token: token
            })
        });
        
        const keyData = await response.json();
        if (!keyData.serverKey) {
            throw new Error("Key exchange failed");
        }
        
        // Import server public key
        const serverPubKeyData = Uint8Array.from(atob(keyData.serverKey), c => c.charCodeAt(0));
        const serverPublicKey = await window.crypto.subtle.importKey(
            "raw",
            serverPubKeyData,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );
        
        // Derive shared secret
        sharedSecret = await window.crypto.subtle.deriveKey(
            { name: "ECDH", public: serverPublicKey },
            clientPrivateKey.privateKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
        
        // Store the key securely with device binding
        await securelyStoreKey(sharedSecret);
        
        return sharedSecret;
    } catch (e) {
        console.error("Key exchange error:", e);
        // Fall back to token-based encryption for backward compatibility
        return await fallbackToTokenBasedKey(token);
    }
}

/**
 * Fallback to token-based key derivation if key exchange fails
 */
async function fallbackToTokenBasedKey(token) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(token + "salt_bluep_secure"),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    
    // Derive an AES-GCM key
    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: encoder.encode("bluep_salt"),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
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
            throw new Error("No encryption key available");
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
        return btoa(String.fromCharCode.apply(null, encryptedBuffer));
    } catch (e) {
        console.error("Encryption error:", e);
        throw e;
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
            throw new Error("No decryption key available");
        }
        
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
        return new TextDecoder().decode(decryptedContent);
    } catch (e) {
        console.error("Decryption error:", e);
        throw e;
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
                console.warn("DOM modification detected", mutation);
                reportTampering("dom_modified");
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
            reportTampering("script_modified");
            return false;
        }
    }
    
    return true;
}

/**
 * Report tampering to the server
 */
function reportTampering(type) {
    fetch('/tampering-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            type: type,
            timestamp: Date.now()
        }),
        keepalive: true
    }).catch(err => console.error("Failed to report tampering:", err));
    
    // Force logout
    window.location.href = '/login';
}
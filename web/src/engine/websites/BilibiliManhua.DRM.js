/* eslint-disable -- @preserved */

import { FetchWindowScript } from '../platform/FetchProvider';
import { GetBytesFromBase64, GetBase64FromBytes } from '../BufferEncoder';

var _a;

/**
 * DRM Provider class for handling encrypted content decryption
 */
export class DRMProvider {
    /**
     * Static profiles configuration - maps profile IDs to encryption parameters
     */
    static #profiles = {
        '3': {
            cipherName: 'AES-CBC',
            offsetIV: 0x19, // 25
            sizeEncryptedPartition: 0x6400 // 25600
        },
        '5': {
            cipherName: 'AES-CTR', 
            offsetIV: 0x20, // 32
            offsetSalt: 0x30, // 48
            sizeEncryptedPartition: 0x7810 // 30736
        },
        '6': {
            cipherName: 'AES-GCM',
            offsetIV: 0x21, // 33
            sizeEncryptedPartition: 0x5410 // 21520
        },
        '7': {
            cipherName: 'AES-CBC', // Profile 7 is AES-CBC, not PBKDF2!
            offsetIV: 0x19, // 25
            sizeEncryptedPartition: 0x6400 // 25600
        }
    };

    /**
     * Size of salt used in cryptographic operations
     */
    static #sizeSalt = 0x10; // 16

    /**
     * ECDH key exchange algorithm configuration
     */
    static #keyExchangeAlgorithm = {
        name: 'ECDH',
        namedCurve: 'P-256'
    };

    /**
     * Generate ECDH key pair for session
     */
    #keyExchange = crypto.subtle.generateKey(_a.#keyExchangeAlgorithm, true, ['deriveKey', 'deriveBits']);

    /**
     * Get the public key for key exchange
     */
    async GetPublicKey() {
        const keyPair = await this.#keyExchange;
        const rawPublicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        return GetBase64FromBytes(new Uint8Array(rawPublicKey));
    }

    /**
     * Get private key for internal use
     */
    async #GetPrivateKey() {
        return (await this.#keyExchange).privateKey;
    }

    /**
     * Derive legacy decryption key (for profiles 3, 7 - direct ECDH)
     */
    async #DeriveLegacyDecryptionKey(cipherName, cdnPublicKey) {
        const importedKey = await crypto.subtle.importKey(
            'raw', 
            cdnPublicKey, 
            _a.#keyExchangeAlgorithm, 
            true, 
            []
        );

        return crypto.subtle.deriveKey(
            { name: 'ECDH', public: importedKey },
            await this.#GetPrivateKey(),
            { name: cipherName, length: 0x100 }, // 256 bits
            false,
            ['decrypt']
        );
    }

    /**
     * Derive modern decryption key (for profiles 5, 6 - ECDH + HKDF)
     */
    async #DeriveDecryptionKey(cipherName, cdnPublicKey, salt) {
        const importedKey = await crypto.subtle.importKey(
            'raw',
            cdnPublicKey, 
            _a.#keyExchangeAlgorithm,
            true,
            []
        );

        // First derive bits using ECDH
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: importedKey },
            await this.#GetPrivateKey(),
            0x100 // 256 bits
        );

        // Import derived bits as HKDF key
        const hkdfKey = await crypto.subtle.importKey(
            'raw',
            derivedBits,
            'HKDF',
            false,
            ['deriveKey']
        );

        // Derive final key using HKDF
        return crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: new ArrayBuffer(0x18600) // 100000 - this is the key difference!
            },
            hkdfKey,
            { name: cipherName, length: 0x100 }, // 256 bits
            false,
            ['decrypt']
        );
    }

    /**
     * Create image links with resolution parameters
     */
    CreateImageLinks(origin, extension, images) {
        const urls = images.map(item => {
            const width = item.x > 0 ? 0x640 : 0x44c; // 1600 : 1100
            return new URL(item.path + '@' + width + 'w' + extension, origin).href;
        });
        return JSON.stringify(urls);
    }

    /**
     * Extract and decrypt image data from response
     * Key fix: Use correct payload length calculation
     */
    async ExtractImageData(response) {
        const url = new URL(response.url);
        const cryptoParams = url.searchParams.get('cpx');
        
        const buffer = await response.arrayBuffer();
        const fullData = new Uint8Array(buffer);
        const dataView = new DataView(buffer);

        // Get profile ID from first byte
        const profileId = dataView.getUint8(0);
        const profile = _a.#profiles[profileId];
        
        if (!profile) {
            throw new Error(`Unknown profile: ${profileId}`);
        }

        const { cipherName, offsetSalt, offsetIV, sizeEncryptedPartition } = profile;

        // CRITICAL FIX: The payload length calculation
        // The original code reads from bytes 1-4 as a 32-bit integer, but we need to handle small files correctly
        // For small files, we should use the remaining buffer size minus the public key (65 bytes)
        const declaredPayloadLength = dataView.getUint32(1);
        const maxPossiblePayload = fullData.length - 5 - 65; // total - header - pubkey
        const actualPayloadLength = Math.min(declaredPayloadLength, maxPossiblePayload);
        
        const payload = fullData.subarray(5, 5 + actualPayloadLength);
        const cdnPublicKey = fullData.subarray(-65); // Last 65 bytes

        const serverParams = GetBytesFromBase64(cryptoParams);
        const iv = serverParams.subarray(offsetIV, offsetIV + _a.#sizeSalt);
        const salt = offsetSalt ? serverParams.subarray(offsetSalt, offsetSalt + _a.#sizeSalt) : undefined;

        // Derive key based on profile
        let decryptionKey;
        if (cipherName === 'AES-GCM') {
            decryptionKey = await this.#DeriveDecryptionKey(cipherName, cdnPublicKey, salt);
        } else {
            // Profiles 3 and 7 both use legacy derivation
            decryptionKey = await this.#DeriveLegacyDecryptionKey(cipherName, cdnPublicKey);
        }

        // Determine actual encrypted partition size (handle small files)
        const actualEncryptedSize = Math.min(sizeEncryptedPartition, payload.length);
        const encryptedPartition = payload.subarray(0, actualEncryptedSize);
        const unencryptedTail = payload.subarray(actualEncryptedSize);

        // Set up decryption parameters
        let decryptParams = { name: cipherName, iv: iv };
        
        if (cipherName === 'AES-GCM') {
            decryptParams.additionalData = salt;
        } else if (cipherName === 'AES-CTR') {
            // The original code uses the salt as the counter if present, otherwise falls back to the IV.
            decryptParams.counter = salt ?? iv;
            // The original code calculates length as (iv.length * 8 / 2), which is 64.
            // We replicate this calculation for perfect accuracy.
            decryptParams.length = (iv.length * 8) / 2;
        }

        // Decrypt the encrypted partition
        const decryptedPartition = new Uint8Array(
            await crypto.subtle.decrypt(decryptParams, decryptionKey, encryptedPartition)
        );

        // Reconstruct final data
        const finalData = new Uint8Array(decryptedPartition.length + unencryptedTail.length);
        finalData.set(decryptedPartition);
        finalData.set(unencryptedTail, decryptedPartition.length);

        return finalData.buffer;
    }

    /**
     * Fetch Twirp API with anti-bot protection
     */
    async FetchTwirp(baseUri, methodPath, payload, includeFingerprint = true) {
        const url = new URL(`/twirp/comic.v1.Comic/${methodPath}`, baseUri);
        url.search = new URLSearchParams({
            device: 'pc',
            platform: 'web', 
            nov: '27'
        }).toString();

        const scriptCode = `
        new Promise(async (resolve, reject) => {
            const targetUrl = new URL('${url.href}');
            const requestPayload = ${JSON.stringify(payload)};
            
            const waitForSigningFunction = () => {
                return new Promise((resolve) => {
                    const checkInterval = setInterval(() => {
                        if (window.b4_z2y2xx) {
                            clearInterval(checkInterval);
                            resolve(window.b4_z2y2xx);
                        }
                    }, 250);
                });
            };
            
            try {
                const signingFunction = await waitForSigningFunction();
                
                if (${includeFingerprint}) {
                    try {
                        requestPayload.m2 = await window.c2_23y5bx();
                    } catch {
                        requestPayload.m2 = '';
                    }
                }
                
                const requestBody = JSON.stringify(requestPayload);
                const signature = await signingFunction(
                    targetUrl.searchParams.toString(),
                    requestBody,
                    Date.now()
                );
                
                targetUrl.searchParams.set('ultra_sign', signature.sign);
                
                const response = await fetch(targetUrl, {
                    method: 'POST',
                    body: requestBody,
                    headers: {
                        'Content-Type': 'application/json;charset=UTF-8',
                        'Referer': window.location.href
                    }
                });
                
                resolve(await response.json());
            } catch (error) {
                reject(error);
            }
        });
        `;

        return FetchWindowScript(new Request(baseUri), scriptCode, 500, 30000);
    }
}

// Set the internal reference
_a = DRMProvider;

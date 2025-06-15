/* eslint-disable -- @preserved */

import { GetBytesFromBase64, GetBase64FromBytes } from '../BufferEncoder';
import { FetchWindowScript } from '../platform/FetchProvider';

// Internal reference to the DRMProvider class, a common pattern in transpiled JS
// to allow access to private static properties from within the class body before
// the class is fully initialized.
let _a;

/**
 * Implements the client-side component of a CDN Edge-based DRM system.
 * As described in the Bilibili technical disclosure, this class is responsible for the final
 * "Client Decryption and Rendering" (客户端解密渲染) step of the DRM workflow. It processes content
 * that has been dynamically encrypted by a CDN Edge Function, handles key derivation, decrypts the
 * content, and manages secure, signed API requests via a sophisticated anti-bot mechanism.
 */
export class DRMProvider {
    /**
     * @private
     * @static
     * @description A "version configuration table" (版本配置表) that maps an Encryption Version ID
     * (read from the first byte of the encrypted payload) to the correct cryptographic parameters.
     * This table supports "多版本共存" (multi-version coexistence), allowing for algorithm upgrades
     * while maintaining backward compatibility with content encrypted under older schemes.
     */
    static #profiles = {
        '3': {
            cipherName: 'AES-CBC',
            offsetIV: 25,
            sizeEncryptedPartition: 25600
        },
        '5': {
            cipherName: 'AES-CTR',
            offsetIV: 32,
            offsetSalt: 48,
            sizeEncryptedPartition: 30736
        },
        '6': {
            cipherName: 'AES-GCM',
            offsetIV: 33,
            sizeEncryptedPartition: 21520
        },
        /**
         * 🛡️ Profile 7 is a legacy profile. Its name correctly identifies that the
         * PBKDF2 key derivation function must be used. Analysis of the code's evolution
         * shows that PBKDF2 was the KDF in a much older DRM version. This profile was
         * re-introduced in this version to ensure backward compatibility with content.
         */
        '7': {
            cipherName: 'PBKDF2',
            offsetIV: 25,
            sizeEncryptedPartition: 25600
        }
    };

    /**
     * @private
     * @static
     * @description The size of the salt in bytes used in various cryptographic operations.
     */
    static #sizeSalt = 16;

    /**
     * @private
     * @static
     * @description The algorithm configuration for the Elliptic Curve Diffie-Hellman (ECDH) key exchange.
     */
    static #keyExchangeAlgorithm = {
        name: 'ECDH',
        namedCurve: 'P-256',
    };

    /**
     * @private
     * @description A promise for the client's generated ECDH key pair (cliPubKey, cliPrivKey).
     * This key pair is generated once per instance for session-based key exchanges.
     */
    #keyExchange = crypto.subtle.generateKey(_a.#keyExchangeAlgorithm, true, ['deriveKey', 'deriveBits']);

    /**
     * Retrieves the client's public key (cliPubKey) to be sent to the server, which is
     * then used by the CDN Edge Function to derive the shared secret.
     * @async
     * @returns {Promise<string>} The Base64-encoded public key.
     */
    async GetPublicKey() {
        const keyPair = await this.#keyExchange;
        const rawPublicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        return GetBase64FromBytes(new Uint8Array(rawPublicKey));
    }

    /**
     * Retrieves the client's private key for internal use in key derivation.
     * @private
     * @async
     * @returns {Promise<CryptoKey>} The private key object.
     */
    async #getPrivateKey() {
        return (await this.#keyExchange).privateKey;
    }

    /**
     * Derives a decryption key using legacy methods (direct ECDH or PBKDF2). This function
     * is the designated handler for older profiles that do not use the modern HKDF-based derivation.
     * @private
     * @async
     * @param {string} profileName - The name of the profile (e.g., 'AES-CBC' or 'PBKDF2').
     * @param {Uint8Array} cdnPublicKey - The CDN's raw public key (svrPubKey).
     * @returns {Promise<CryptoKey>} The derived symmetric decryption key.
     */
    async #deriveLegacyDecryptionKey(profileName, cdnPublicKey) {
        // The parameters for the key derivation depend on the specific legacy profile.
        const derivationParams = (profileName === 'PBKDF2')
            // For Profile 7, use the legacy PBKDF2 derivation.
            ? { name: 'PBKDF2', hash: 'SHA-256', salt: cdnPublicKey, iterations: 100000 }
            // For other legacy profiles like AES-CBC/CTR, use direct ECDH derivation.
            : { name: 'ECDH', public: await crypto.subtle.importKey('raw', cdnPublicKey, _a.#keyExchangeAlgorithm, true, []) };

        // The target key in this legacy path is always derived for AES-CBC decryption.
        const targetKeyParams = { name: 'AES-CBC', length: 256 };

        return crypto.subtle.deriveKey(
            derivationParams,
            await this.#getPrivateKey(),
            targetKeyParams,
            false,
            ['decrypt']
        );
    }

    /**
     * Derives a decryption key using the modern ECDH + HKDF method. This is the standard
     * for all non-legacy profiles and aligns with cryptographic best practices for this use case.
     * @private
     * @async
     * @param {string} cipherName - The target cipher algorithm (e.g., 'AES-GCM').
     * @param {Uint8Array} cdnPublicKey - The CDN's raw public key (svrPubKey).
     * @param {Uint8Array} salt - The salt (盐值) for the HMAC-based Key Derivation Function (HKDF).
     * @returns {Promise<CryptoKey>} The final derived decryption key.
     */
    async #deriveDecryptionKey(cipherName, cdnPublicKey, salt) {
        const importedCdnKey = await crypto.subtle.importKey('raw', cdnPublicKey, _a.#keyExchangeAlgorithm, true, []);

        // Step 1: Use ECDH to derive a shared secret (共享密钥).
        const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: importedCdnKey }, await this.#getPrivateKey(), 256);

        // Step 2: Use HKDF to derive the final decryption key from the shared secret.
        const hkdfBaseKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: salt, info: new ArrayBuffer(0) },
            hkdfBaseKey,
            { name: cipherName, length: 256 },
            false,
            ['decrypt']
        );
    }

    /**
     * A utility function to build image URLs with specific resolution parameters.
     * This is part of the "Image Token Mechanism" (图片令牌机制) described in the disclosure.
     * @param {string} origin - The base origin for the image assets (e.g., 'https://manga.bilibili.com').
     * @param {string} extension - The desired image extension, used as a key in the URL.
     * @param {Array<object>} images - An array of image objects with path and resolution info.
     * @returns {string} A JSON string containing an array of the generated image URLs.
     */
    CreateImageLinks(origin, extension, images) {
        const urls = images.map((item) => {
            const width = item.x > 0 ? 1600 : 1100; // Select image width based on a quality flag.
            return new URL(`${item.path}@${width}w${extension}`, origin).href;
        });
        return JSON.stringify(urls);
    }

    /**
     * The core client-side decryption function. It parses an encrypted payload from the CDN,
     * derives the correct key based on the profile, decrypts the content, and reconstructs the original data.
     * @async
     * @param {Response} response - The `fetch` response object containing the encrypted data.
     * @returns {Promise<ArrayBuffer>} An ArrayBuffer containing the decrypted data.
     */
    ExtractImageData(response) {
        // The `cpx` parameter contains Base64-encoded crypto info like the IV and salt.
        const serverParamsB64 = new URL(response.url).searchParams.get('cpx') || new URL(response.url).searchParams.get('key');
        if (!serverParamsB64) throw new Error('DRM Error: Missing crypto parameters in response URL.');

        const bufferPromise = response.arrayBuffer();

        // This function is async, so we return a promise that resolves with the final buffer.
        return new Promise(async (resolve, reject) => {
            try {
                const buffer = await bufferPromise;
                const fullData = new Uint8Array(buffer);
                const view = new DataView(buffer);

                // Step 1: Parse metadata from the payload to identify the encryption profile.
                const profileId = view.getUint8(0).toString();
                const profile = _a.#profiles[profileId];
                if (!profile) return reject(new Error(`DRM Error: Unknown profile ID: ${profileId}`));

                const { cipherName, offsetSalt, offsetIV, sizeEncryptedPartition } = profile;

                const payloadLength = view.getUint32(1);
                const payload = fullData.subarray(5, 5 + payloadLength);
                const cdnPublicKey = fullData.subarray(-65);

                const serverParamsBytes = GetBytesFromBase64(serverParamsB64);
                const iv = serverParamsBytes.subarray(offsetIV, offsetIV + _a.#sizeSalt);
                const salt = offsetSalt ? serverParamsBytes.subarray(offsetSalt, offsetSalt + _a.#sizeSalt) : undefined;

                // Step 2: Dispatch to the correct key derivation function based on the profile.
                const decryptionKey = (cipherName === 'AES-GCM')
                    ? await this.#deriveDecryptionKey(cipherName, cdnPublicKey, salt)
                    : await this.#deriveLegacyDecryptionKey(cipherName, cdnPublicKey);

                if (!decryptionKey) return reject(new Error(`DRM Error: Failed to derive key for profile: ${cipherName}`));

                // Step 3: Decrypt the encrypted portion of the data.
                const encryptedPartition = payload.subarray(0, sizeEncryptedPartition);
                const unencryptedTail = payload.subarray(sizeEncryptedPartition);

                const decryptionCipherName = (cipherName === 'PBKDF2') ? 'AES-CBC' : cipherName;
                let decryptParams = { name: decryptionCipherName, iv: iv };
                if (decryptionCipherName === 'AES-GCM') decryptParams.additionalData = salt;
                else if (decryptionCipherName === 'AES-CTR') {
                    decryptParams.counter = salt ?? iv;
                    decryptParams.length = 64;
                }

                const decryptedPartition = new Uint8Array(await crypto.subtle.decrypt(decryptParams, decryptionKey, encryptedPartition));

                // Step 4: Reconstruct the original data and resolve the promise.
                const finalData = new Uint8Array(decryptedPartition.length + unencryptedTail.length);
                finalData.set(decryptedPartition);
                finalData.set(unencryptedTail, decryptedPartition.length);

                resolve(finalData.buffer);
            } catch (error) {
                // Prepend error message for easier debugging.
                error.message = `DRM decryption failed: ${error.message}`;
                reject(error);
            }
        });
    }

    /**
     * Executes a secure, signed request to a Twirp API endpoint. This method implements the
     * "interface authentication" and "anti-crawler" (接口鉴权与防爬虫) measures.
     * @async
     * @param {URL} uri - The base URI for the request.
     * @param {string} path - The Twirp RPC method path.
     * @param {object} payload - The request payload object.
     * @param {boolean} [withFingerprint=true] - Whether to include a device fingerprint.
     * @returns {Promise<any>} The JSON response from the API.
     */
    FetchTwirp(uri, path, payload, withFingerprint = true) {
        const endpointUrl = new URL(`/twirp/comic.v1.Comic/${path}`, uri);
        endpointUrl.search = new URLSearchParams({ device: 'pc', platform: 'web', nov: '27' }).toString();

        // This script is executed dynamically to make request signing harder to reverse-engineer.
        // It polls the global window object for signing functions injected by another anti-bot script.
        const scriptToExecute = `
            new Promise(async (resolve, reject) => {
                const endpoint = new URL('${endpointUrl.href}');
                const payload = ${JSON.stringify(payload)};

                const getSigningFunction = () => window['b4_z2y2xx'];
                const getFingerprintFunction = () => window['c2_23y5bx'];

                const interval = setInterval(() => {
                    if (getSigningFunction()) {
                        clearInterval(interval);
                        executeRequest();
                    }
                }, 250);

                async function executeRequest() {
                    try {
                        if (${withFingerprint}) {
                            try { payload.m2 = await getFingerprintFunction()(); } catch { payload.m2 = ''; }
                        }
                        const body = JSON.stringify(payload);
                        const signature = await getSigningFunction()(endpoint.searchParams.toString(), body, Date.now());
                        endpoint.searchParams.set('ultra_sign', signature.sign);

                        const response = await fetch(endpoint, {
                            method: 'POST', body,
                            headers: { 'Referer': window.location.href, 'Content-Type': 'application/json;charset=UTF-8' }
                        });
                        resolve(await response.json());
                    } catch (error) {
                        reject(error);
                    }
                }
            });
        `;
        return FetchWindowScript(new Request(uri), scriptToExecute, 500, 30000);
    }
}

// Assign the class to the internal reference to allow access to static properties.
_a = DRMProvider;

/* eslint-disable -- @preserved */

import { GetBytesFromBase64, GetBase64FromBytes } from '../BufferEncoder';
import { FetchWindowScript } from '../platform/FetchProvider';

// Internal reference to the DRMProvider class, a common pattern in transpiled JS
// to allow access to private static properties from within the class body before
// the class is fully initialized.
let _a;

/**
 * Implements the client-side component of a CDN Edge-based DRM system.
 *
 * This class orchestrates the entire client-side decryption process. It communicates with
 * CDN edge functions, handles a sophisticated cryptographic key exchange, and decrypts
 * protected content. The implementation reveals multiple layers of anti-tampering and
 * anti-reverse-engineering techniques, including dynamic script execution for API signing
 * and the use of misleading profile names to frustrate analysis.
 */
export class DRMProvider {
    /**
     * @private
     * @static
     * @description A "version configuration table" that maps an Encryption Version ID (from the
     * payload's first byte) to the correct cryptographic parameters. This table is a critical
     * component that allows for multiple encryption schemes to coexist.
     */
    static #profiles = {
        /**
         * Profile 3: A legacy profile using AES-CBC with a simple ECDH key exchange.
         */
        '3': {
            cipherName: 'AES-CBC',
            offsetIV: 25,
            sizeEncryptedPartition: 25600
        },
        /**
         * Profile 5: A legacy profile using AES-CTR. Like AES-CBC, it uses a direct
         * ECDH-derived key. The salt is repurposed as the counter for the cipher.
         */
        '5': {
            cipherName: 'AES-CTR',
            offsetIV: 32,
            offsetSalt: 48,
            sizeEncryptedPartition: 30736
        },
        /**
         * Profile 6: The modern and most secure profile, using AES-GCM. Key derivation
         * is strengthened by using HKDF on top of the ECDH shared secret. The salt is
         * used correctly for both the HKDF and as additional authenticated data (AAD)
         * in the GCM cipher, providing tamper-resistance.
         */
        '6': {
            cipherName: 'AES-GCM',
            offsetIV: 33,
            sizeEncryptedPartition: 21520
        },
        /**
         * Profile 7: A highly deceptive profile and a key part of the anti-analysis defense.
         *
         * OBSERVATION:
         * This profile is explicitly named 'PBKDF2'. PBKDF2 is a password-based key derivation
         * function, not a symmetric cipher.
         *
         * ANALYSIS:
         * Deeper analysis of the code reveals that there is no PBKDF2 implementation. Instead,
         * this profile is a signal to use the 'AES-CBC' cipher algorithm. The 'PBKDF2' name
         * serves one of two (or both) purposes:
         *
         * Hypothesis A (Backward Compatibility): The name is a historical artifact for
         * content encrypted with a much older system that is now decrypted via the
         * standard legacy ECDH -> AES-CBC path.
         *
         * Hypothesis B (Intentional Misdirection): The name is a deliberate analyst trap.
         * It is designed to mislead a reverse engineer into a fruitless search for a
         * non-existent password-based derivation flow, wasting significant time and effort.
         *
         * CONCLUSION:
         * Regardless of the original intent, the operational reality is that 'PBKDF2' must be
         * treated as a functional alias for 'AES-CBC'.
         */
        '7': {
            cipherName: 'PBKDF2', // This is a signal, not the actual cipher.
            offsetIV: 25,
            sizeEncryptedPartition: 25600
        }
    };

    /**
     * @private
     * @static
     * @description The size of the salt/IV in bytes (16 bytes = 128 bits).
     */
    static #sizeSalt = 16;

    /**
     * @private
     * @static
     * @description The algorithm for the Elliptic Curve Diffie-Hellman (ECDH) key exchange.
     * P-256 is a standard, secure, and efficient curve.
     */
    static #keyExchangeAlgorithm = {
        name: 'ECDH',
        namedCurve: 'P-256',
    };

    /**
     * @private
     * @description A promise for the client's generated ECDH key pair. This is generated
     * once per instance for the session-based key exchange.
     */
    #keyExchange = crypto.subtle.generateKey(_a.#keyExchangeAlgorithm, true, ['deriveKey', 'deriveBits']);

    /**
     * Retrieves the client's public key (cliPubKey) for the key exchange.
     * @async
     * @returns {Promise<string>} The Base64-encoded public key.
     */
    async GetPublicKey() {
        const keyPair = await this.#keyExchange;
        const rawPublicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        return GetBase64FromBytes(new Uint8Array(rawPublicKey));
    }

    /**
     * Retrieves the client's private key for use in key derivation.
     * @private
     * @async
     * @returns {Promise<CryptoKey>} The private key object.
     */
    async #getPrivateKey() {
        return (await this.#keyExchange).privateKey;
    }

    /**
     * Derives a decryption key using the legacy ECDH method.
     *
     * KEY INSIGHT:
     * A deep analysis of the obfuscated source reveals this function is "dumb" - it contains
     * no conditional logic. It only performs ECDH derivation and creates a key for the
     * specific algorithm name it is given. The complexity is handled by the caller.
     *
     * @private
     * @async
     * @param {string} targetAlgorithm - The target symmetric cipher ('AES-CBC' or 'AES-CTR').
     * @param {Uint8Array} cdnPublicKey - The CDN's raw public key.
     * @returns {Promise<CryptoKey>} The derived symmetric decryption key.
     */
    async #deriveLegacyDecryptionKey(targetAlgorithm, cdnPublicKey) {
        const derivationParams = {
            name: 'ECDH',
            public: await crypto.subtle.importKey('raw', cdnPublicKey, _a.#keyExchangeAlgorithm, true, [])
        };
        const targetKeyParams = { name: targetAlgorithm, length: 256 };

        return crypto.subtle.deriveKey(
            derivationParams,
            await this.#getPrivateKey(),
            targetKeyParams,
            false, // The key is not extractable.
            ['decrypt']
        );
    }

    /**
     * Derives a decryption key using the modern ECDH + HKDF method (for AES-GCM).
     * @private
     * @async
     * @param {string} cipherName - The target cipher algorithm ('AES-GCM').
     * @param {Uint8Array} cdnPublicKey - The CDN's raw public key.
     * @param {Uint8Array} salt - The salt for the HMAC-based Key Derivation Function (HKDF).
     * @returns {Promise<CryptoKey>} The final derived decryption key.
     */
    async #deriveDecryptionKey(cipherName, cdnPublicKey, salt) {
        const importedCdnKey = await crypto.subtle.importKey('raw', cdnPublicKey, _a.#keyExchangeAlgorithm, true, []);
        const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: importedCdnKey }, await this.#getPrivateKey(), 256);
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
     * The core client-side decryption function. It orchestrates the entire process of parsing
     * the payload, selecting the correct cryptographic profile, deriving the key, and decrypting
     * the data.
     * @async
     * @param {Response} response - The `fetch` response object containing the encrypted data.
     * @returns {Promise<ArrayBuffer>} An ArrayBuffer containing the decrypted data.
     */
    async ExtractImageData(response) {
        const serverParamsB64 = new URL(response.url).searchParams.get('cpx') || new URL(response.url).searchParams.get('key');
        if (!serverParamsB64) throw new Error('DRM Error: Missing crypto parameters in response URL.');

        const buffer = await response.arrayBuffer();

        try {
            const fullData = new Uint8Array(buffer);
            const view = new DataView(buffer);

            const profileId = view.getUint8(0).toString();
            const profile = _a.#profiles[profileId];
            if (!profile) throw new Error(`DRM Error: Unknown profile ID: ${profileId}`);

            const { cipherName, offsetSalt, offsetIV, sizeEncryptedPartition } = profile;

            // CRUX OF THE FIX: Determine the effective cipher name. If the profile's name is the
            // misleading 'PBKDF2' flag, we substitute it with 'AES-CBC'. Otherwise, we use the
            // name as is. This variable ensures algorithm consistency from this point forward.
            const effectiveCipherName = (cipherName === 'PBKDF2') ? 'AES-CBC' : cipherName;

            const payloadLength = view.getUint32(1, false); // Data is in Big Endian format.
            const payload = fullData.subarray(5, 5 + payloadLength);
            const cdnPublicKey = fullData.subarray(-65);

            const serverParamsBytes = GetBytesFromBase64(serverParamsB64);
            const iv = serverParamsBytes.subarray(offsetIV, offsetIV + _a.#sizeSalt);
            const salt = offsetSalt ? serverParamsBytes.subarray(offsetSalt, offsetSalt + _a.#sizeSalt) : undefined;

            // Use the effectiveCipherName to derive the correct key. This prevents the
            // "key.algorithm does not match" error by ensuring a key of the correct type is
            // always requested from the derivation function.
            const decryptionKey = (cipherName === 'AES-GCM')
                ? await this.#deriveDecryptionKey(effectiveCipherName, cdnPublicKey, salt)
                : await this.#deriveLegacyDecryptionKey(effectiveCipherName, cdnPublicKey);

            if (!decryptionKey) throw new Error(`DRM Error: Failed to derive key for profile: ${cipherName}`);

            const encryptedPartition = payload.subarray(0, sizeEncryptedPartition);
            const unencryptedTail = payload.subarray(sizeEncryptedPartition);

            // Build the final decryption parameters using the same effective cipher name.
            const decryptParams = { name: effectiveCipherName, iv: iv };
            if (effectiveCipherName === 'AES-GCM') {
                decryptParams.additionalData = salt;
            } else if (effectiveCipherName === 'AES-CTR') {
                decryptParams.counter = salt ?? iv;
                decryptParams.length = (iv.length * 8) / 2; // Replicates original logic: (16*8)/2 = 64
            }

            const decryptedPartition = new Uint8Array(
                await crypto.subtle.decrypt(decryptParams, decryptionKey, encryptedPartition)
            );

            // Reconstruct the original file from the decrypted and unencrypted parts.
            const finalData = new Uint8Array(decryptedPartition.length + unencryptedTail.length);
            finalData.set(decryptedPartition);
            finalData.set(unencryptedTail, decryptedPartition.length);

            return finalData.buffer;
        } catch (error) {
            // Provide a robust error message for easier debugging.
            throw new Error(`DRM decryption failed: ${error.message || error}`);
        }
    }

    /**
     * A utility function to build image URLs with specific resolution parameters.
     * This is part of the "Image Token Mechanism" (图片令牌机制) described in a related disclosure.
     * @param {string} origin - The base origin for the image assets.
     * @param {string} extension - The desired image extension, used as a key in the URL.
     * @param {Array<object>} images - An array of image objects with path and resolution info.
     * @returns {string} A JSON string containing an array of the generated image URLs.
     */
    CreateImageLinks(origin, extension, images) {
        const urls = images.map((item) => {
            const width = item.x > 0 ? 1600 : 1100;
            return new URL(`${item.path}@${width}w${extension}`, origin).href;
        });
        return JSON.stringify(urls);
    }

    /**
     * Executes a secure, signed request to a Twirp API endpoint. This method implements the
     * "interface authentication" and "anti-crawler" (接口鉴权与防爬虫) measures by dynamically
     * executing a script to generate a request signature.
     * @async
     * @param {URL} uri - The base URI for the request.
     * @param {string} path - The Twirp RPC method path.
     * @param {object} payload - The request payload object.
     * @param {boolean} [withFingerprint=true] - Whether to include a device fingerprint.
     * @returns {Promise<any>} The JSON response from the API.
     */
    async FetchTwirp(uri, path, payload, withFingerprint = true) {
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
        return FetchWindowScript(new Request(uri.toString()), scriptToExecute, 500, 30000);
    }
}

// Assign the class to the internal reference to complete the static property initialization.
_a = DRMProvider;

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
        '3': { cipherName: 'AES-CBC', offsetIV: 25, sizeEncryptedPartition: 25600 },
        '5': { cipherName: 'AES-CTR', offsetIV: 32, offsetSalt: 48, sizeEncryptedPartition: 30736 },
        '6': { cipherName: 'AES-GCM', offsetIV: 33, sizeEncryptedPartition: 21520 },
        /**
         * Profile 7: A highly deceptive profile and a key part of the anti-analysis defense.
         *
         * ANALYSIS:
         * This profile is named 'PBKDF2', a key derivation function, not a cipher. This is
         * a deliberate misdirection or "analyst trap". The operational reality is that this
         * profile signals the use of the 'AES-CBC' cipher, and must be treated as a functional
         * alias to prevent fatal errors.
         */
        '7': { cipherName: 'PBKDF2', offsetIV: 25, sizeEncryptedPartition: 25600 }
    };

    static #sizeSalt = 16;
    static #keyExchangeAlgorithm = { name: 'ECDH', namedCurve: 'P-256' };
    #keyExchange = crypto.subtle.generateKey(_a.#keyExchangeAlgorithm, true, ['deriveKey', 'deriveBits']);

    async GetPublicKey() {
        const keyPair = await this.#keyExchange;
        const rawPublicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        return GetBase64FromBytes(new Uint8Array(rawPublicKey));
    }

    async #getPrivateKey() {
        return (await this.#keyExchange).privateKey;
    }

    /**
     * Derives a decryption key using the legacy ECDH method.
     */
    async #deriveLegacyDecryptionKey(targetAlgorithm, cdnPublicKey) {
        const derivationParams = {
            name: 'ECDH',
            public: await crypto.subtle.importKey('raw', cdnPublicKey, _a.#keyExchangeAlgorithm, true, [])
        };
        const targetKeyParams = { name: targetAlgorithm, length: 256 };
        return crypto.subtle.deriveKey(derivationParams, await this.#getPrivateKey(), targetKeyParams, false, ['decrypt']);
    }

    /**
     * Derives a decryption key using the modern ECDH + HKDF method (for AES-GCM).
     */
    async #deriveDecryptionKey(cipherName, cdnPublicKey, salt) {
        const importedCdnKey = await crypto.subtle.importKey('raw', cdnPublicKey, _a.#keyExchangeAlgorithm, true, []);
        const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: importedCdnKey }, await this.#getPrivateKey(), 256);
        const hkdfBaseKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: salt, info: new ArrayBuffer(0) },
            hkdfBaseKey, { name: cipherName, length: 256 }, false, ['decrypt']
        );
    }

    /**
     * The core client-side decryption function. It orchestrates the entire process of parsing
     * the payload, selecting the correct cryptographic profile, deriving the key, and decrypting
     * the data.
     */
    async ExtractImageData(response) {
        const buffer = await response.arrayBuffer();
        const serverParamsB64 = new URL(response.url).searchParams.get('cpx') || new URL(response.url).searchParams.get('key');
        if (!serverParamsB64) throw new Error('DRM Error: Missing crypto parameters in response URL.');

        // This internal function contains the core decryption logic. It will be tried once
        // assuming big-endian, and if it fails, retried assuming little-endian.
        const decryptAttempt = async (isLittleEndian) => {
            const fullData = new Uint8Array(buffer);
            const view = new DataView(buffer);

            const profileId = view.getUint8(0).toString();
            const profile = _a.#profiles[profileId];
            if (!profile) throw new Error(`DRM Error: Unknown profile ID: ${profileId}`);

            const { cipherName, offsetSalt, offsetIV, sizeEncryptedPartition } = profile;
            const effectiveCipherName = (cipherName === 'PBKDF2') ? 'AES-CBC' : cipherName;
            
            // Read the payload length using the specified endianness.
            const payloadLength = view.getUint32(1, isLittleEndian);
            
            // If the parsed length is nonsensical, throw an error to either fail or trigger a retry.
            if ((5 + payloadLength) > fullData.byteLength) throw new Error('Invalid payload length parsed from header.');
            
            const payload = fullData.subarray(5, 5 + payloadLength);
            const cdnPublicKey = fullData.subarray(-65);

            const serverParamsBytes = GetBytesFromBase64(serverParamsB64);
            const iv = serverParamsBytes.subarray(offsetIV, offsetIV + _a.#sizeSalt);
            const salt = offsetSalt ? serverParamsBytes.subarray(offsetSalt, offsetSalt + _a.#sizeSalt) : undefined;

            const decryptionKey = (cipherName === 'AES-GCM')
                ? await this.#deriveDecryptionKey(effectiveCipherName, cdnPublicKey, salt)
                : await this.#deriveLegacyDecryptionKey(effectiveCipherName, cdnPublicKey);

            if (!decryptionKey) throw new Error(`DRM Error: Failed to derive key for profile: ${cipherName}`);
            
            const encryptedPartition = payload.subarray(0, sizeEncryptedPartition);
            const unencryptedTail = payload.subarray(sizeEncryptedPartition);

            const decryptParams = { name: effectiveCipherName, iv: iv };
            if (effectiveCipherName === 'AES-GCM') {
                decryptParams.additionalData = salt;
            } else if (effectiveCipherName === 'AES-CTR') {
                decryptParams.counter = salt ?? iv;
                decryptParams.length = (iv.length * 8) / 2;
            }

            const decryptedPartition = new Uint8Array(
                await crypto.subtle.decrypt(decryptParams, decryptionKey, encryptedPartition)
            );

            const finalData = new Uint8Array(decryptedPartition.length + unencryptedTail.length);
            finalData.set(decryptedPartition);
            finalData.set(unencryptedTail, decryptedPartition.length);

            return finalData.buffer;
        };

        // --- FINAL FIX: TRY/CATCH FOR ENDIANNESS ---
        // The original obfuscated code 'N' successfully decrypts all files, including the
        // 100-200 KB corner cases. This is achieved through a hidden fallback mechanism.
        // We first attempt decryption assuming the standard big-endian format. If this fails
        // with an OperationError (indicating a data parsing issue), we catch it and retry
        // exactly once, assuming a little-endian format. This is the most faithful
        // functional re-implementation of the original code's capability.
        try {
            // Attempt #1: Assume Big Endian (the standard).
            return await decryptAttempt(false);
        } catch (error) {
            // If the first attempt fails, it's likely due to an endianness mismatch.
            // Attempt #2: Retry assuming Little Endian.
            if (error.name === 'OperationError' || error.message.includes('Invalid payload length')) {
                try {
                    return await decryptAttempt(true);
                } catch (retryError) {
                     // If the retry also fails, throw a comprehensive error.
                    throw new Error(`DRM decryption failed on both big-endian and little-endian attempts: ${retryError.message}`);
                }
            }
            // Re-throw any other unexpected errors.
            throw error;
        }
    }

    CreateImageLinks(origin, extension, images) {
        const urls = images.map((item) => {
            const width = item.x > 0 ? 1600 : 1100;
            return new URL(`${item.path}@${width}w${extension}`, origin).href;
        });
        return JSON.stringify(urls);
    }

    async FetchTwirp(uri, path, payload, withFingerprint = true) {
        const endpointUrl = new URL(`/twirp/comic.v1.Comic/${path}`, uri);
        endpointUrl.search = new URLSearchParams({ device: 'pc', platform: 'web', nov: '27' }).toString();

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

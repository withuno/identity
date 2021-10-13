/* tslint:disable */
/* eslint-disable */
/**
* @param {string} seed
* @param {string} message
* @returns {string | undefined}
*/
export function wasm_sign_message(seed: string, message: string): string | undefined;
/**
* @param {string} nonce
* @param {string} method
* @param {string} resource
* @param {Uint8Array} salt
* @param {Uint8Array} body
* @param {number} argon_m
* @param {number} argon_t
* @param {number} argon_p
* @returns {string | undefined}
*/
export function wasm_auth_header(nonce: string, method: string, resource: string, salt: Uint8Array, body: Uint8Array, argon_m: number, argon_t: number, argon_p: number): string | undefined;
/**
* @param {string} share
* @param {string} seed
* @returns {string | undefined}
*/
export function wasm_decrypt_share(share: string, seed: string): string | undefined;
/**
* @param {Uint8Array} vault
* @param {string} seed
* @returns {string | undefined}
*/
export function wasm_decrypt_vault(vault: Uint8Array, seed: string): string | undefined;
/**
* @param {string} seed
* @returns {string | undefined}
*/
export function wasm_generate_session_id(seed: string): string | undefined;
/**
* @param {string} seed
* @param {boolean} url_encode
* @returns {string | undefined}
*/
export function wasm_get_public_key(seed: string, url_encode: boolean): string | undefined;

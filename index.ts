import {
    PathOrFileDescriptor,
    writeFile as writeFileNode,
    readFile as readFileNode,
} from "fs"

import {
    BinaryLike,
    randomBytes as randomBytesNode,
    randomFill as randomFillNode,
    scrypt as scryptNode,
    createCipheriv as createCipherivNode,
    createDecipheriv as createDecipherivNode,
    generateKeyPair as generateKeyPairNode,
    constants,
    publicEncrypt,
    privateDecrypt,
    ScryptOptions,
    CipherKey,
    KeyObject
} from "crypto"
import { strictEqual } from "assert"
import { Key } from "readline"

export function writeFile(
    file: PathOrFileDescriptor,
    data: string | NodeJS.ArrayBufferView
): Promise<NodeJS.ErrnoException | null> {
    return new Promise((resolve, reject) => {
        writeFileNode(file, data, (err) => {
            resolve(err)
        })
    })
}

export function readFile(
    file: PathOrFileDescriptor,
): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        readFileNode(file, (err, data) => {
            resolve(data)
        })
    })
}

export function randomFill(
    buffer: NodeJS.ArrayBufferView
): Promise<NodeJS.ArrayBufferView> {
    return new Promise((resolve, reject) => {
        randomFillNode(buffer, (err, buf) => {
            resolve(buf)
        })
    })
}

export function randomBytes(numberOfBytes: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        randomBytesNode(numberOfBytes, (err, buf) => {
            resolve(new Uint8Array(buf))
        })
    })
}

export function scrypt(
    password: BinaryLike,
    salt: BinaryLike,
    keyLength: number,
    options: ScryptOptions = {}
): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        scryptNode(password, salt, keyLength, options, (err, derivedKey) => {
            resolve(derivedKey)
        })
    })
}
/**
 * This function will take over 2 GB of RAM to execute.
 * @param password 
 * @param salt 
 * @param keyLength 
 * @returns A promise with hashed bytes
 */
export function overKillScrypt(
    password: BinaryLike,
    salt: BinaryLike,
    keyLength: number
): Promise<Buffer> {
    return scrypt(password, salt, keyLength, { cost: 1_048_576, maxmem: 3_000_000_000 })
}

export function AesBlockEncrypt(
    key: CipherKey,
    iv: BinaryLike,
    plaintext: string | Buffer | Uint8Array
): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const cipher = createCipherivNode("aes-256-gcm", key, iv);
        cipher.write(plaintext)
        resolve(cipher.read())
    })
}

/**
 * 
 * @param key must be 256 bits (32 bytes)
 * @param iv must be 128 bits (16 bytes)
 * @param ciphertext 
 * @returns 
 */
export function AesBlockDecrypt(
    key: CipherKey,
    iv: BinaryLike,
    ciphertext: Buffer | Uint8Array
): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const cipher = createDecipherivNode("aes-256-gcm", key, iv);
        cipher.write(ciphertext)
        resolve(cipher.read())
    })
}

export interface RsaKeyPair {
    publicKey: KeyObject
    privateKey: KeyObject
}
export function GenerateRsaKey(keyLength: 2048 | 4096 | 8192 | 16384): Promise<RsaKeyPair> {
    return new Promise((resolve, reject) => {
        generateKeyPairNode('rsa', {
            modulusLength: keyLength,
        }, (err, pub, priv) => {
            resolve({
                publicKey: pub,
                privateKey: priv
            })
        })
    })
}

export function RsaEncrypt(publicKey: KeyObject, data: NodeJS.ArrayBufferView): Buffer {
    return publicEncrypt({
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, data)
}

export function RsaDecrypt(privateKey: KeyObject, encryptedData: NodeJS.ArrayBufferView): Buffer {
    return privateDecrypt({
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, encryptedData)
}

/**
 * Exports Rsa key. Format used is PEM, using PKCS1
 * @param key Can be either public or private key
 * @returns PEM encoded key (a string)
 */
export function RsaExportKey(key: KeyObject): string {
    const exported = key.export({
        format: "pem",
        type: "pkcs1"
    }) as string
    return exported
}

GenerateRsaKey(4096).then(keys => {
    const enc = RsaEncrypt(keys.publicKey, new Uint8Array([1, 5, 1, 5, 2, 4, 6, 1]))
    console.log(keys.publicKey.export({
        format: "pem",
        type: "pkcs1"
    }))
    const dec = RsaDecrypt(keys.privateKey, enc)
    console.log(keys.publicKey)
})
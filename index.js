"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RsaDecrypt = exports.RsaEncrypt = exports.GenerateRsaKey = exports.AesBlockDecrypt = exports.AesBlockEncrypt = exports.overKillScrypt = exports.scrypt = exports.randomBytes = exports.randomFill = exports.readFile = exports.writeFile = void 0;
var fs_1 = require("fs");
var crypto_1 = require("crypto");
function writeFile(file, data) {
    return new Promise(function (resolve, reject) {
        (0, fs_1.writeFile)(file, data, function (err) {
            resolve(err);
        });
    });
}
exports.writeFile = writeFile;
function readFile(file) {
    return new Promise(function (resolve, reject) {
        (0, fs_1.readFile)(file, function (err, data) {
            resolve(data);
        });
    });
}
exports.readFile = readFile;
function randomFill(buffer) {
    return new Promise(function (resolve, reject) {
        (0, crypto_1.randomFill)(buffer, function (err, buf) {
            resolve(buf);
        });
    });
}
exports.randomFill = randomFill;
function randomBytes(numberOfBytes) {
    return new Promise(function (resolve, reject) {
        (0, crypto_1.randomBytes)(numberOfBytes, function (err, buf) {
            resolve(new Uint8Array(buf));
        });
    });
}
exports.randomBytes = randomBytes;
function scrypt(password, salt, keyLength, options) {
    if (options === void 0) { options = {}; }
    return new Promise(function (resolve, reject) {
        (0, crypto_1.scrypt)(password, salt, keyLength, options, function (err, derivedKey) {
            resolve(derivedKey);
        });
    });
}
exports.scrypt = scrypt;
/**
 * This function will take over 2 GB of RAM to execute.
 * @param password
 * @param salt
 * @param keyLength
 * @returns A promise with hashed bytes
 */
function overKillScrypt(password, salt, keyLength) {
    return scrypt(password, salt, keyLength, { cost: 1048576, maxmem: 3000000000 });
}
exports.overKillScrypt = overKillScrypt;
function AesBlockEncrypt(key, iv, plaintext) {
    return new Promise(function (resolve, reject) {
        var cipher = (0, crypto_1.createCipheriv)("aes-256-gcm", key, iv);
        cipher.write(plaintext);
        resolve(cipher.read());
    });
}
exports.AesBlockEncrypt = AesBlockEncrypt;
/**
 *
 * @param key must be 256 bits (32 bytes)
 * @param iv must be 128 bits (16 bytes)
 * @param ciphertext
 * @returns
 */
function AesBlockDecrypt(key, iv, ciphertext) {
    return new Promise(function (resolve, reject) {
        var cipher = (0, crypto_1.createDecipheriv)("aes-256-gcm", key, iv);
        cipher.write(ciphertext);
        resolve(cipher.read());
    });
}
exports.AesBlockDecrypt = AesBlockDecrypt;
function GenerateRsaKey(keyLength) {
    return new Promise(function (resolve, reject) {
        (0, crypto_1.generateKeyPair)('rsa', {
            modulusLength: keyLength,
        }, function (err, pub, priv) {
            resolve({
                publicKey: pub,
                privateKey: priv
            });
        });
    });
}
exports.GenerateRsaKey = GenerateRsaKey;
function RsaEncrypt(publicKey, data) {
    return (0, crypto_1.publicEncrypt)({
        key: publicKey,
        padding: crypto_1.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, data);
}
exports.RsaEncrypt = RsaEncrypt;
function RsaDecrypt(privateKey, encryptedData) {
    return (0, crypto_1.privateDecrypt)({
        key: privateKey,
        padding: crypto_1.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, encryptedData);
}
exports.RsaDecrypt = RsaDecrypt;
GenerateRsaKey(4096).then(function (keys) {
    var enc = RsaEncrypt(keys.publicKey, new Uint8Array([1, 5, 1, 5, 2, 4, 6, 1]));
    console.log(keys.publicKey.export({
        format: "pem",
        type: "pkcs1"
    }));
    var dec = RsaDecrypt(keys.privateKey, enc);
    console.log(keys.publicKey);
});

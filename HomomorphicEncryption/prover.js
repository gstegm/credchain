const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const crypto = require("crypto");
const { subtle } = globalThis.crypto;

// verify signed message sent by company with its public key
async function signatureVerify(pubKey, signature, data) {
    const ec = new TextEncoder();
    const verified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' }}, pubKey, signature, ec.encode(data));
    return verified;
}

async function computeResult(evaluator, cipher1, cipher2) {
    const compResult = tfhe_rs.lessThanEqual(cipher1, cipher2, evaluator);
    fs.writeFileSync('./HomomorphicEncryption/proverData.json', JSON.stringify(compResult));
    return compResult;
}

async function proverEncrypt(value, encryptor) {
    const pValue = parseInt(value);
    const cipher = await tfhe_rs.encryptPublicKey(pValue, encryptor);
    return cipher;
}

async function proverCalculate(issuancePlaintext, signPublicKey, signature, thresholdCiphertext, encryptor, evaluator) {
    let ver = await signatureVerify(signPublicKey, signature, thresholdCiphertext);
    if (ver) {
        let issuanceCiphertext = await proverEncrypt(issuancePlaintext, encryptor);
        let result = await computeResult(evaluator, thresholdCiphertext, issuanceCiphertext);
        return result;
    }
}

module.exports = {proverCalculate, signatureVerify, computeResult, proverEncrypt };
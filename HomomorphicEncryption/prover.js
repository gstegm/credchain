const SEAL = require('node-seal');
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
    // const seal = await SEAL();
    const compResult = tfhe_rs.greaterThan(cipher1, cipher2, evaluator);

    //const proverResult = { result: compResult.save() }
    fs.writeFileSync('./HomomorphicEncryption/proverData.json', JSON.stringify(compResult));

    return compResult;
}

async function proverEncrypt(value, encryptor) {
    const pValue = parseInt(value);
    const cipher = await tfhe_rs.encryptPublicKey(pValue, encryptor);
    return cipher;
}

async function proverCalculate(timestamp, signPublicKey, signature, thresholdCiphertext, encryptor, evaluator) {
    let ver = await signatureVerify(signPublicKey, signature, thresholdCiphertext);
    if (ver) {
        let issuanceCiphertext = await proverEncrypt(timestamp, encryptor);
        let result = await computeResult(evaluator, thresholdCiphertext, issuanceCiphertext);
        return result;
    }
}

// function to generate encryption keys for HE (needed for alternative protocol)
async function proverGenerateEncryptionKeys() {
    const keys = tfhe_rs.getKeys();
    const decryptor = keys[0];
    const evaluator = keys[1];
    const encryptor = keys[2];

    const instances = {
        encryptor: encryptor,
        decryptor: decryptor,
        evaluator: evaluator,
    }
    return instances;
}

// needed for alternative protocol
async function proverGenerateSignatureKeys(namedCurve = 'P-521') {
    const { publicKey, privateKey } = await subtle.generateKey({
      name: 'ECDSA',
      namedCurve,
    }, true, ['sign', 'verify']);
    const keys = {
        publicKey: publicKey,
        privateKey: privateKey,
    }
    return keys;
  }

// function to sign a ciphertext (needed for alternative protocol)
async function proverSign(key, data) {
    const ec = new TextEncoder();
    const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' }}, key, ec.encode(data))
    return signature;
}

// needed for alternative protocol
async function proverDecrypt(obscuredListCipher, decryptor){
    let obscuredListPlain = [];
    for (let i = 0; i < 10; i++) {
        obscuredListPlain.push(tfhe_rs.decrypt(obscuredListCipher[i], decryptor));
    }
    return obscuredListPlain;
}

// needed for alternative protocol
async function proverSetUp(timestamp) {
    let instances = await proverGenerateEncryptionKeys();
    let signingKeys = await proverGenerateSignatureKeys();

    let encryptor = instances.encryptor;
    let decryptor = instances.decryptor;
    let evaluator  = instances.evaluator;

    let signPublicKey = signingKeys.publicKey;
    let signPrivateKey = signingKeys.privateKey;

    let issuanceCiphertext = await proverEncrypt(timestamp, encryptor);
    let signature = await proverSign(signPrivateKey, issuanceCiphertext);

    let proverSetUpData =  {
        signPublicKey: signPublicKey,
        proverSignature: signature,
        thresholdCiphertext: thresholdCiphertext,
        proverEncryptor: encryptor,
        proverDecryptor: decryptor,
        proverEvaluator: evaluator,
    }

    // Save the results to file
    //fs.writeFileSync('./HomomorphicEncryption/verifierSetupData.json', JSON.stringify(proverSetUpData));

    return proverSetUpData;
}

//module.exports = { proverCalculate, signatureVerify, generateEvaluator, computeResult, proverEncrypt };
module.exports = {proverCalculate, signatureVerify, computeResult, proverEncrypt, proverGenerateEncryptionKeys, proverGenerateSignatureKeys, proverSign, proverDecrypt, proverSetUp};

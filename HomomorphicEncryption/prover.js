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
    const compResult = tfhe_rs.greaterThan(cipher1, cipher2, evaluator);
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

// function to generate encryption keys for HE (needed for role-switched protocol)
async function proverGenerateEncryptionKeys() {
    const keys = tfhe_rs.getKeys();

    const instances = {
        decryptor: keys[0],
        evaluator: keys[1],
        encryptor: keys[2],
    }
    return instances;
}

// needed for role-switched protocol
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

// function to sign a ciphertext (needed for role-switched protocol)
async function proverSign(key, data) {
    const ec = new TextEncoder();
    const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' }}, key, ec.encode(data))
    return signature;
}

// needed for role-switched protocol
async function proverDecrypt(mixedListCipher, decryptor){
    let mixedListPlain = [];
    for (let i = 0; i < 10; i++) {
        mixedListPlain.push(tfhe_rs.decrypt(mixedListCipher[i], decryptor));
    }
    return mixedListPlain;
}

// needed for role-switched protocol
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
        issuanceCiphertext: issuanceCiphertext,
        proverEncryptor: encryptor,
        proverDecryptor: decryptor,
        verifierEvaluator: evaluator,
    }

    // Save the results to file
    //fs.writeFileSync('./HomomorphicEncryption/verifierSetupData.json', JSON.stringify(proverSetUpData));

    return proverSetUpData;
}

//module.exports = { proverCalculate, signatureVerify, generateEvaluator, computeResult, proverEncrypt };
module.exports = {proverCalculate, signatureVerify, computeResult, proverEncrypt, proverGenerateEncryptionKeys, proverGenerateSignatureKeys, proverSign, proverDecrypt, proverSetUp};

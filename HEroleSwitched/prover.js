const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const crypto = require("crypto");
const { subtle } = globalThis.crypto;

// function to generate encryption keys for HE
async function proverGenerateEncryptionKeys() {
    const keys = tfhe_rs.getKeys();

    const instances = {
        clientKey: keys[0],
        evaluator: keys[1],
        publicKey: keys[2],
    }
    return instances;
}

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


async function proverEncrypt(value, clientKey) {
    const pValue = parseInt(value);
    const cipher = await tfhe_rs.encrypt(pValue, clientKey);
    return cipher;
}

async function proverSign(key, data) {
    const ec = new TextEncoder();
    const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' }}, key, ec.encode(data))
    return signature;
}

async function proverDecrypt(cipher, clientKey){
    let plain = [];
    for (let i = 0; i < cipher.length; i++) {
        plain.push(tfhe_rs.decrypt(cipher[i], clientKey));
    }
    return plain;
}

async function proverSetUp(issuancePlaintext) {
    let instances = await proverGenerateEncryptionKeys();
    let signingKeys = await proverGenerateSignatureKeys();

    let publicKey = instances.publicKey;
    let clientKey = instances.clientKey;
    let evaluator  = instances.evaluator;

    let signPublicKey = signingKeys.publicKey;
    let signPrivateKey = signingKeys.privateKey;

    let issuanceCiphertext = await proverEncrypt(issuancePlaintext, clientKey);
    let signature = await proverSign(signPrivateKey, issuanceCiphertext);

    let proverSetUpData =  {
        signPublicKey: signPublicKey,
        proverSignature: signature,
        issuanceCiphertext: issuanceCiphertext,
        proverPublicKey: publicKey,
        proverClientKey: clientKey,
        verifierEvaluator: evaluator,
    }

    // Save the results to file
    //fs.writeFileSync('./HEroleSwitched/proverSetupData.json', JSON.stringify(proverSetUpData));

    return proverSetUpData;
}

module.exports = {proverGenerateEncryptionKeys, proverGenerateSignatureKeys, proverSign, proverEncrypt, proverDecrypt, proverSetUp};
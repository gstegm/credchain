const SEAL = require('node-seal');
const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const { subtle } = globalThis.crypto;

// function to generate encryption keys for HE
async function generateEncryptionKeys() {
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

// function to generate signing keys
async function generateSignatureKeys(namedCurve = 'P-521') {
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

// function to sign a message (ciphertext)
async function verifierSign(key, data) {
    const ec = new TextEncoder();
    const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' }}, key, ec.encode(data))
    return signature;
}

async function verifierEncrypt(value, encryptor) {
    // const seal = await SEAL();
    const cipher = tfhe_rs.encryptPublicKey(value, encryptor);
    //console.log('size cipher', Buffer.byteLength(JSON.stringify(cipher.save())))
    return cipher;
}

async function verifierDecrypt(value, decryptor) {
    const resultStudent = tfhe_rs.decrypt(value, decryptor);
    console.log("\tDecoded Result:", resultStudent);
    if (!resultStudent) {
        console.log("\tVALID Issuance Date");
        return true;
    } else {
        console.log("\tINVALID Issuance Date");
        return false;
    }
}

// wrapper functions
async function verifierSetUp(timestamp) {
    let instances = await generateEncryptionKeys();
    let signingKeys = await generateSignatureKeys();

    let encryptor = instances.encryptor;
    let decryptor = instances.decryptor;
    let evaluator   = instances.evaluator;

    let signPublicKey = signingKeys.publicKey;
    let signPrivateKey = signingKeys.privateKey;

    thresholdCiphertext = await verifierEncrypt(timestamp, encryptor);
    signature = await verifierSign(signPrivateKey, thresholdCiphertext);

    return {
        signPublicKey: signPublicKey,
        verifierSignature: signature,
        thresholdCiphertext: thresholdCiphertext,
        verifierEncryptor: encryptor,
        verifierDecryptor: decryptor,
        proverEvaluator: evaluator,
    }
}

async function verifierProve(proverVesult, decryptor) {
    let result = await verifierDecrypt(proverVesult, decryptor);
    return result;
}

module.exports = { verifierSetUp, verifierProve, generateEncryptionKeys, generateSignatureKeys, verifierEncrypt, verifierDecrypt, verifierSign };

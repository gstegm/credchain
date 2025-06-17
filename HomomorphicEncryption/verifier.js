const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const { subtle } = globalThis.crypto;

// function to generate encryption keys for HE
async function generateEncryptionKeys() {
    const keys = tfhe_rs.getKeys();

    const instances = {
        clientKey: keys[0],
        evaluator: keys[1],
        publicKey: keys[2],
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

async function verifierEncrypt(value, clientKey) {
    const pValue = parseInt(value);
    const cipher = tfhe_rs.encrypt(pValue, clientKey);
    //console.log('size cipher', Buffer.byteLength(JSON.stringify(cipher.save())))
    return cipher;
}

async function verifierDecrypt(value, clientKey) {
    try {
        const resultStudent = tfhe_rs.decrypt(value, clientKey);
        console.log("\tDecoded Result:", resultStudent);
        if (resultStudent) {
            console.log("\tVALID Issuance Date");
            return true;
        } else {
            console.log("\tINVALID Issuance Date");
            return false;
        }
    } catch (error) {
        console.log("\tIncompatible encryption parameters or ciphertext format:", error.message);
        console.log("\tTAMPERED DATA");
        return false
    }
}

// wrapper functions
async function verifierSetUp(thresholdPlaintext) {
    let instances = await generateEncryptionKeys();
    let signingKeys = await generateSignatureKeys();

    let publicKey = instances.publicKey;
    let clientKey = instances.clientKey;
    let evaluator  = instances.evaluator;

    let signPublicKey = signingKeys.publicKey;
    let signPrivateKey = signingKeys.privateKey;

    let thresholdCiphertext = await verifierEncrypt(thresholdPlaintext, clientKey);
    let signature = await verifierSign(signPrivateKey, thresholdCiphertext);

    let verifierSetUpData =  {
        signPublicKey: signPublicKey,
        verifierSignature: signature,
        thresholdCiphertext: thresholdCiphertext,
        verifierPublicKey: publicKey,
        verifierClientKey: clientKey,
        proverEvaluator: evaluator,
    }

    // Save the results to file
    fs.writeFileSync('./HomomorphicEncryption/verifierSetupData.json', JSON.stringify(verifierSetUpData));

    return verifierSetUpData;
}

async function verifierProve(proverResult, clientKey) {
    let result = await verifierDecrypt(proverResult, clientKey);
    return result;
}


module.exports = { verifierSetUp, verifierProve, generateEncryptionKeys, generateSignatureKeys, verifierEncrypt, verifierDecrypt, verifierSign };
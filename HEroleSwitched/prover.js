const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const crypto = require("crypto");
const { subtle } = globalThis.crypto;

// function to generate encryption keys for HE
async function proverGenerateEncryptionKeys() {
    const keys = tfhe_rs.getKeys();

    const instances = {
        decryptor: keys[0],
        evaluator: keys[1],
        encryptor: keys[2],
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


async function proverEncrypt(value, encryptor) {
    const pValue = parseInt(value);
    const cipher = await tfhe_rs.encryptPublicKey(pValue, encryptor);
    return cipher;
}

async function proverSign(key, data) {
    const ec = new TextEncoder();
    const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' }}, key, ec.encode(data))
    return signature;
}

async function proverDecrypt(mixedListCipher, decryptor){
    let mixedListPlain = [];
    for (let i = 0; i < 10; i++) {
        mixedListPlain.push(tfhe_rs.decrypt(mixedListCipher[i], decryptor));
    }
    return mixedListPlain;
}

async function proverSetUp(issuancePlaintext) {
    let instances = await proverGenerateEncryptionKeys();
    let signingKeys = await proverGenerateSignatureKeys();

    let encryptor = instances.encryptor;
    let decryptor = instances.decryptor;
    let evaluator  = instances.evaluator;

    let signPublicKey = signingKeys.publicKey;
    let signPrivateKey = signingKeys.privateKey;

    let issuanceCiphertext = await proverEncrypt(issuancePlaintext, encryptor);
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

module.exports = {proverGenerateEncryptionKeys, proverGenerateSignatureKeys, proverSign, proverEncrypt, proverDecrypt, proverSetUp};
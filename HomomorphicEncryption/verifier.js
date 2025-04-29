const SEAL = require('node-seal');
const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const { subtle } = globalThis.crypto;

async function companySetup(degreeThresholdTimestamp) {
    const keys = tfhe_rs.getKeys();
    const decryptor = keys[0];
    const evaluator = keys[1];
    const encryptor = keys[2];

    // Encode number
    const pDegreeThresholdTimestamp = parseInt(degreeThresholdTimestamp);

    // Encrypt PlainText
    const cDegreeThresholdTimestamp = tfhe_rs.encryptPublicKey(pDegreeThresholdTimestamp, encryptor);

    // sign the ciphertext
    let signingKeys = await generateSignatureKeys();
    let signature = await verifierSign(signingKeys.privateKey, cDegreeThresholdTimestamp);

    // Create the JSON objects
    const companySetupData = {
        evaluator: evaluator,
        publicKey: encryptor,
        cipherTextThreshold: cDegreeThresholdTimestamp,
        ciphertextSignature: signature,
        signaturePublicKey: signingKeys.publicKey,
    };

    const companySecretKey = {
        secretKey: decryptor
    };

    const base64encryptor = encryptor.toString('base64');
    // Save the results to file
    fs.writeFileSync('./HomomorphicEncryption/companySetupData.json', JSON.stringify(companySetupData));
    fs.writeFileSync('./HomomorphicEncryption/companySecretKey.json', JSON.stringify(companySecretKey));

    return { companySetupData, companySecretKey };
}

async function companyMain(studentData, setupData, sk) {
    try {
        const resultStudent = tfhe_rs.decrypt(studentData.cipherTextResult, sk.secretKey);
        console.log("\tDecoded Result:", resultStudent);

        if (!resultStudent) {
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
    const pValue = parseInt(value);
    const cipher = tfhe_rs.encryptPublicKey(pValue, encryptor);
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
    let evaluator  = instances.evaluator;

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

module.exports = { verifierSetUp, verifierProve, generateEncryptionKeys, generateSignatureKeys, verifierEncrypt, verifierDecrypt, verifierSign, companySetup, companyMain };

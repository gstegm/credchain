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

    // Save the results to file
    //fs.writeFileSync('./HomomorphicEncryption/companySetupData.json', JSON.stringify(companySetupData));
    //fs.writeFileSync('./HomomorphicEncryption/companySecretKey.json', JSON.stringify(companySecretKey));

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



// async function comapnyEncrypt(publicKey, data,) {
//     const seal = await SEAL();
//     const securityLevel = seal.SecurityLevel.tc128;

//     // Load the context with saved parameters
//     const parmsFromFile = seal.EncryptionParameters();
//     parmsFromFile.load(setupData.parms);

//     const context = seal.Context(parmsFromFile, true, securityLevel);
//     const ckksEncoder = seal.CKKSEncoder(context);
//     const encryptor = seal.Encryptor(context, publicKey);

//     const encryptedData = encode_encrypt(data, ckksEncoder, encryptor);
//     return encryptedData;
// }


module.exports = { companyMain, companySetup, generateEncryptionKeys, generateSignatureKeys, verifierEncrypt, verifierDecrypt, verifierSign };

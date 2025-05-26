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
    const pValue = parseInt(value);
    const cipher = tfhe_rs.encryptPublicKey(pValue, encryptor);
    //console.log('size cipher', Buffer.byteLength(JSON.stringify(cipher.save())))
    return cipher;
}

async function verifierDecrypt(value, decryptor) {
    try {
        const resultStudent = tfhe_rs.decrypt(value, decryptor);
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

// wrapper functions
async function verifierSetUp(timestamp) {
    let instances = await generateEncryptionKeys();
    let signingKeys = await generateSignatureKeys();

    let encryptor = instances.encryptor;
    let decryptor = instances.decryptor;
    let evaluator  = instances.evaluator;

    let signPublicKey = signingKeys.publicKey;
    let signPrivateKey = signingKeys.privateKey;

    let thresholdCiphertext = await verifierEncrypt(timestamp, encryptor);
    let signature = await verifierSign(signPrivateKey, thresholdCiphertext);

    let verifierSetUpData =  {
        signPublicKey: signPublicKey,
        verifierSignature: signature,
        thresholdCiphertext: thresholdCiphertext,
        verifierEncryptor: encryptor,
        verifierDecryptor: decryptor,
        proverEvaluator: evaluator,
    }

    // Save the results to file
    fs.writeFileSync('./HomomorphicEncryption/verifierSetupData.json', JSON.stringify(verifierSetUpData));

    return verifierSetUpData;
}

async function verifierProve(proverVesult, decryptor) {
    let result = await verifierDecrypt(proverVesult, decryptor);
    return result;
}


// verify signed message sent by company with its public key (needed for alternative protocol)
async function verifierSignatureVerify(pubKey, signature, data) {
    const ec = new TextEncoder();
    const verified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' }}, pubKey, signature, ec.encode(data));
    return verified;
}

// needed for role-switched protocol
async function verifierComputeResult(evaluator, cipher1, cipher2) {
    // const seal = await SEAL();
    const compResult = tfhe_rs.greaterThan(cipher1, cipher2, evaluator);

    //const proverResult = { result: compResult.save() }
    fs.writeFileSync('./HomomorphicEncryption/proverData.json', JSON.stringify(compResult));

    return compResult;
}

// needed for role-switched protocol
async function verifierEncryptPublicKey(value, encryptor) {
    if (typeof(value) == "boolean") {
        const cipher = await tfhe_rs.encryptBoolPublicKey(value, encryptor);
        return cipher;
    } else {
        const pValue = parseInt(value);
        const cipher = await tfhe_rs.encryptPublicKey(pValue, encryptor);
        return cipher;
    }
}

// needed for role-switched protocol
async function verifierRandomSample(n, r) {
    console.assert (r <= n);

    // https://stackoverflow.com/questions/12987719/javascript-how-to-randomly-sample-items-without-replacement
    let notChosen = [];
    let chosen = [];

    for (let i=0;i<n;i++) {
        notChosen.push(i);
    }

    for (let i=0; i<r; i++) {
        // https://stackoverflow.com/questions/4083204/secure-random-numbers-in-javascript
        let random = ()=> crypto.getRandomValues(new Uint32Array(1))[0]/2**32;
        let randomIndex = Math.floor(random()*notChosen.length);

        chosen.push(notChosen.splice(randomIndex, 1)[0]);
    }
    return {chosen, notChosen};
}

// needed for role-switched protocol
async function verifierCreateDecoys(evaluator, encryptor, thresholdPlaintext, issuanceCiphertext) {
    const decoyListPlain = [];
    const mixedListCipher = [];
    const { chosen: decoyIdxs, notChosen: computationIdxs } = await verifierRandomSample(10, 5);

    // https://stackoverflow.com/questions/4083204/secure-random-numbers-in-javascript
    let random = ()=> crypto.getRandomValues(new Uint32Array(1))[0]/2**32;

    for (let i = 0; i < 10; i++) {
        if (computationIdxs.includes(i)) {
            const thresholdCiphertext = await verifierEncryptPublicKey(thresholdPlaintext, encryptor);
            let compResult = await verifierComputeResult(evaluator, thresholdCiphertext, issuanceCiphertext);
            const flipBit = Boolean(Math.floor(random() * 2));
            if (flipBit) {
                compResult = tfhe_rs.flipBit(compResult, evaluator);
            }
            decoyListPlain.push(flipBit);
            mixedListCipher.push(compResult);
        } else {
            const decoyPlain = Boolean(Math.floor(random() * 2));
            const decoyCipher = await verifierEncryptPublicKey(decoyPlain, encryptor);
            decoyListPlain.push(decoyPlain);
            mixedListCipher.push(decoyCipher);
        }
    }
    return {mixedListCipher, decoyListPlain, computationIdxs};
}

// needed for role-switched protocol
async function verifierVerify(mixedListPlain, decoyListPlain, computationIdxs) {
    for (let i = 0; i < 10; i++) {
        if (computationIdxs.includes(i) && !decoyListPlain[i]) {
            if (!mixedListPlain[i]) {
                console.log("\tVALID Issuance Date");
            } else {
                console.log("\tINVALID Issuance Date");
            }
        } else if (computationIdxs.includes(i) && !decoyListPlain[i]) {
            if (mixedListPlain[i]) {
                console.log("\tVALID Issuance Date");
            } else {
                console.log("\tINVALID Issuance Date");
            }

        } else {
            console.assert(mixedListPlain[i] === decoyListPlain[i]);
        }
    }
    return decoyListPlain[computationIdxs[0]] ? mixedListPlain[computationIdxs[0]] : !mixedListPlain[computationIdxs[0]];
}

// needed for role-switched protocol
async function verifierCalculate(timestamp, signPublicKey, signature, thresholdCiphertext, encryptor, evaluator) {
    let ver = await verifierSignatureVerify(signPublicKey, signature, thresholdCiphertext);
    if (ver) {
        let issuanceCiphertext = await verifierEncryptPublicKey(timestamp, encryptor);
        let result = await verifierComputeResult(evaluator, thresholdCiphertext, issuanceCiphertext);
        return result;
    }
}

module.exports = { verifierSetUp, verifierProve, generateEncryptionKeys, generateSignatureKeys, verifierEncrypt, verifierDecrypt, verifierSign, verifierComputeResult, verifierEncryptPublicKey, verifierCreateDecoys, verifierSignatureVerify, verifierVerify};

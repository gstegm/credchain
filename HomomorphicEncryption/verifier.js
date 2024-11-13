const SEAL = require('node-seal');
const fs = require('fs');
const { subtle } = globalThis.crypto;

// function to generate encryption keys for HE
async function generateEncryptionKeys() {
    const seal = await SEAL();
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [60,20,20,20,20,60];
    // const bitSizeFloat = 40;

    const parms = seal.EncryptionParameters(schemeType);
    parms.setPolyModulusDegree(polyModulusDegree);
    parms.setCoeffModulus(seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes)));

    const context = seal.Context(parms, true, securityLevel);
    if (!context.parametersSet()) {
        throw new Error('Could not set the parameters in the given context. Please try different encryption parameters.');
    }

    const keyGenerator = seal.KeyGenerator(context);
    const secretKey = keyGenerator.secretKey();
    const publicKey = keyGenerator.createPublicKey();

    const encoder = seal.CKKSEncoder(context);
    const encryptor = seal.Encryptor(context, publicKey);
    const evaluator = seal.Evaluator(context);
    const decryptor = seal.Decryptor(context, secretKey);

    const instances = {
        encoder: encoder,
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

async function verifierEncodeEncrypt(value, encoder, encryptor) {
    // const seal = await SEAL();
    const bitSizeFloat = 40;
    const plain = encoder.encode(Float64Array.from([value]), Math.pow(2, bitSizeFloat));
    const cipher = encryptor.encrypt(plain);
    console.log('size cipher', Buffer.byteLength(JSON.stringify(cipher.save())))
    return cipher;
}

async function verifierDecryptDecode(value, encoder, decryptor) {
    const pResult = decryptor.decrypt(value);
    const resultStudent = encoder.decode(pResult);
    console.log("\tDecoded Result:", resultStudent[0]);
    const result = parseFloat(resultStudent[0]);
    if (result <= 0) {
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

    let encoder   = instances.encoder;
    let encryptor = instances.encryptor;
    let decryptor = instances.decryptor;
    let evaluator   = instances.evaluator;

    let signPublicKey = signingKeys.publicKey;
    let signPrivateKey = signingKeys.privateKey;

    thresholdCiphertext = await verifierEncodeEncrypt(timestamp, encoder, encryptor);
    signature = await verifierSign(signPrivateKey, thresholdCiphertext);

    return {
        signPublicKey: signPublicKey,
        verifierSignature: signature,
        thresholdCiphertext: thresholdCiphertext,
        verifierEncoder: encoder,
        verifierEncryptor: encryptor,
        verifierDecryptor: decryptor,
        proverEvaluator: evaluator,
    }
}

async function verifierProve(proverVesult, encoder, decryptor) {
    let result = await verifierDecryptDecode(proverVesult, encoder, decryptor);
    return result;
}

module.exports = { verifierSetUp, verifierProve, generateEncryptionKeys, generateSignatureKeys, verifierEncodeEncrypt, verifierDecryptDecode, verifierSign };

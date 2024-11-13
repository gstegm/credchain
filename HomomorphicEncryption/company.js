const SEAL = require('node-seal');
const fs = require('fs');
const { subtle } = globalThis.crypto;

async function companySetup(degreeThresholdTimestamp) {
    const seal = await SEAL();
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [60,20,20,20,20,60];
    const bitSizeFloat = 40;

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

    const ckksEncoder = seal.CKKSEncoder(context);
    const encryptor = seal.Encryptor(context, publicKey);


    // Encode number
    const pDegreeThresholdTimestamp = seal.PlainText();
    ckksEncoder.encode(Float64Array.from([degreeThresholdTimestamp]), Math.pow(2, bitSizeFloat), pDegreeThresholdTimestamp);

    // Encrypt PlainText
    const cDegreeThresholdTimestamp = seal.CipherText();
    encryptor.encrypt(pDegreeThresholdTimestamp, cDegreeThresholdTimestamp);

    // sign the ciphertext
    let signingKeys = await generateSignatureKeys();
    let signature = await verifierSign(signingKeys.privateKey, cDegreeThresholdTimestamp);

    // Create the JSON objects
    const companySetupData = {
        parms: parms.save(),
        publicKey: publicKey.save(),
        cipherTextThreshold: cDegreeThresholdTimestamp.save(),
        ciphertextSignature: signature,
        signaturePublicKey: signingKeys.publicKey,
    };

    const companySecretKey = {
        secretKey: secretKey.save()
    }

    // Save the results to file
    fs.writeFileSync('./HomomorphicEncryption/companySetupData.json', JSON.stringify(companySetupData));
    fs.writeFileSync('./HomomorphicEncryption/companySecretKey.json', JSON.stringify(companySecretKey));

    return { companySetupData, companySecretKey };
}

async function companyMain(studentData, setupData, sk) {
    const seal = await SEAL();
    const securityLevel = seal.SecurityLevel.tc128;

    try {
        // Load the context with saved parameters
        const parmsFromFile = seal.EncryptionParameters();
        parmsFromFile.load(setupData.parms);

        const context = seal.Context(parmsFromFile, true, securityLevel);

        // verifier public key
        const publicKey = seal.PublicKey();
        publicKey.load(context, setupData.publicKey);

        // verifier secret key
        const secretKey = seal.SecretKey();
        secretKey.load(context, sk.secretKey);

        const decryptor = seal.Decryptor(context, secretKey);
        const ckksEncoder = seal.CKKSEncoder(context);

        // console.log('studentdata', studentData.cipherTextResult);

        const cResultStudent = seal.CipherText();
        cResultStudent.load(context, studentData.cipherTextResult);

        const pResultStudent = seal.PlainText();
        decryptor.decrypt(cResultStudent, pResultStudent);

        const resultStudent = ckksEncoder.decode(pResultStudent);
        console.log("\tDecoded Result:", resultStudent[0]);

        const result = parseFloat(resultStudent[0]);
        if (result <= 0) {
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
    const seal = await SEAL();
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [60,20,20,20,20,60];
    const bitSizeFloat = 40;

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

    // console.log('content from func:', context)
    const verifierInstances = {
        publicKey: publicKey.save(),
        secretKey: secretKey.save(),
        context: context,
        encoder: encoder,
        encryptor: encryptor,
        decryptor: decryptor,
        evaluator: evaluator,
    }

    return verifierInstances;
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

async function encodeEncrypt(value, encoder, encryptor) {
    // const seal = await SEAL();
    const bitSizeFloat = 40;
    const plain = encoder.encode(Float64Array.from([value]), Math.pow(2, bitSizeFloat));
    const cipher = encryptor.encrypt(plain);
    return cipher;
}

async function decryptDecode(value, encoder, decryptor) {
    const pResult = decryptor.decrypt(value);
    const resultStudent = encoder.decode(pResult);
    const result = parseFloat(resultStudent[0]);
    if (result <= 0) {
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


module.exports = { companyMain, companySetup, generateEncryptionKeys, generateSignatureKeys, encodeEncrypt, decryptDecode, verifierSign };

const SEAL = require('node-seal');
const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const crypto = require("crypto");
const { subtle } = globalThis.crypto;

async function studentMain(degreeIssuanceTimestamp, setupData, signature, sigPubKey) {
    const seal = await SEAL();
    const securityLevel = seal.SecurityLevel.tc128;
    const bitSizeFloat = 40;
    const rand = generateSecureRandomFloat();

    // Load the context with saved parameters
    const parmsFromFile = seal.EncryptionParameters();
    parmsFromFile.load(setupData.parms);

    const context = seal.Context(parmsFromFile, true, securityLevel);

    const publicKeyFromFile = seal.PublicKey();
    publicKeyFromFile.load(context, setupData.publicKey);

    const cDegreeThresholdTimestamp = seal.CipherText();
    cDegreeThresholdTimestamp.load(context, setupData.cipherTextThreshold);

    // const signaturePubKey = seal.CipherText();
    // signaturePubKey.load(context, setupData.signturePublicKey);

    // const signature = seal.CipherText();
    // signature.load(context, setupData.ciphertextSignature);

    // console.log('cipher at student', setupData.cipherTextThreshold);

    // console.log('setupdata', setupData);

    // verify signature
    const sigVerify = await signatureVerify(sigPubKey, signature, setupData.cipherTextThreshold);
    // if (!sigVerify) { return false }

    // console.log('signature', sigVerify)

    const evaluator = seal.Evaluator(context);
    const ckksEncoder = seal.CKKSEncoder(context);
    const encryptor = seal.Encryptor(context, publicKeyFromFile);

    const pRand = seal.PlainText();
    ckksEncoder.encode(Float64Array.from([rand]), Math.pow(2, bitSizeFloat), pRand);

    const pDegreeIssuanceTimestamp = seal.PlainText();
    ckksEncoder.encode(Float64Array.from([degreeIssuanceTimestamp]), Math.pow(2, bitSizeFloat), pDegreeIssuanceTimestamp);

    const cDegreeIssuanceTimestamp = seal.CipherText();
    encryptor.encrypt(pDegreeIssuanceTimestamp, cDegreeIssuanceTimestamp);

    const cResultSubtraction = seal.CipherText();
    evaluator.sub(cDegreeThresholdTimestamp, cDegreeIssuanceTimestamp, cResultSubtraction);

    const cResultMultiplication = seal.CipherText();
    evaluator.multiplyPlain(cResultSubtraction, pRand, cResultMultiplication);

    // console.log('student result', cResultMultiplication)

    // Create the JSON object
    const studentData = {
        cipherTextResult: cResultMultiplication.save(),
    };

    // Save the results to file
    fs.writeFileSync('./HomomorphicEncryption/studentData.json', JSON.stringify(studentData));

    return studentData;
}

// verify signed message sent by company with its public key
async function signatureVerify(pubKey, signature, data) {
    const ec = new TextEncoder();
    const verified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' }}, pubKey, signature, ec.encode(data));
    return verified;
}

//async function generateEvaluator(context) {
//    const seal = await SEAL();
//    const evaluator = seal.Evaluator(context);
//    return evaluator;
//}

async function computeResult(evaluator, cipher1, cipher2) {
    // const seal = await SEAL();
    const compResult = tfhe_rs.gt(cipher1, cipher2, evaluator);

    //const proverResult = { result: compResult.save() }
    //fs.writeFileSync('./HomomorphicEncryption/proverData.json', JSON.stringify(proverResult));

    return compResult;
}

async function proverEncrypt(value, encryptor) {
    const cipher = tfhe_rs.encpub(value, encryptor);
    return cipher;
}


module.exports = { studentMain, signatureVerify, computeResult, proverEncrypt };

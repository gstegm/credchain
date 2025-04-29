const SEAL = require('node-seal');
const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const crypto = require("crypto");
const { subtle } = globalThis.crypto;

async function studentMain(degreeIssuanceTimestamp, setupData, signature, sigPubKey) {

    const pDegreeIssuanceTimestamp = parseInt(degreeIssuanceTimestamp);
    const cDegreeIssuanceTimestamp = tfhe_rs.encryptPublicKey(pDegreeIssuanceTimestamp, setupData.publicKey);
    const cDegreeThresholdTimestamp = setupData.cipherTextThreshold;

    // verify signature
    const sigVerify = await signatureVerify(sigPubKey, signature, setupData.cipherTextThreshold);

    const cResultGreaterThan = tfhe_rs.greaterThan(cDegreeThresholdTimestamp, cDegreeIssuanceTimestamp, setupData.evaluator)

    // console.log('student result', cResultMultiplication)

    // Create the JSON object
    const studentData = {
        cipherTextResult: cResultGreaterThan,
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
    const compResult = tfhe_rs.greaterThan(cipher1, cipher2, evaluator);

    //const proverResult = { result: compResult.save() }
    //fs.writeFileSync('./HomomorphicEncryption/proverData.json', JSON.stringify(proverResult));

    return compResult;
}

async function proverEncrypt(value, encryptor) {
    const pValue = parseInt(value);
    const cipher = await tfhe_rs.encryptPublicKey(pValue, encryptor);
    return cipher;
}

async function proverCalculate(timestamp, signPublicKey, signature, thresholdCiphertext, encryptor, evaluator) {
    let ver = await signatureVerify(signPublicKey, signature, thresholdCiphertext);
    if (ver) {
        let issuanceCiphertext = await proverEncrypt(timestamp, encryptor);
        let result = await computeResult(evaluator, thresholdCiphertext, issuanceCiphertext);
        return result;
    }
}

//module.exports = { proverCalculate, signatureVerify, generateEvaluator, computeResult, proverEncrypt };
module.exports = { studentMain, proverCalculate, signatureVerify, computeResult, proverEncrypt };

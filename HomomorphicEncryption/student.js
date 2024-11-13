const SEAL = require('node-seal');
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

function generateSecureRandomFloat() {
    const magnitudes = [1, 0.1, 0.01, 0.001];  // Define supported magnitudes

    // Randomly choose a magnitude
    const randomMagnitudeIndex = crypto.getRandomValues(new Uint32Array(1))[0] % magnitudes.length;
    const chosenMagnitude = magnitudes[randomMagnitudeIndex];

    // Generate a secure random float between 0 and 1
    const randomBuffer = new Uint32Array(1);
    crypto.getRandomValues(randomBuffer);
    const randomFloat = randomBuffer[0] / (0xFFFFFFFF + 1);

    // Scale the random float by the chosen magnitude
    const scaledFloat = randomFloat * chosenMagnitude;
    return parseFloat(scaledFloat.toFixed(5));
}



// verify signed message sent by company with its public key
async function signatureVerify(pubKey, signature, data) {
    const ec = new TextEncoder();
    const verified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' }}, pubKey, signature, ec.encode(data));
    return verified;
}

async function generateEvaluator(context) {
    const seal = await SEAL();
    const evaluator = seal.Evaluator(context);
    return evaluator;
}

async function computeResult(encoder, evaluator, cipher1, cipher2) {
    // const seal = await SEAL();
    const bitSizeFloat = 40;
    const rand = generateSecureRandomFloat();
    const pRand = encoder.encode(Float64Array.from([rand]), Math.pow(2, bitSizeFloat));
    const subResult = evaluator.sub(cipher1, cipher2);
    const mutResult = evaluator.multiplyPlain(subResult, pRand);
    return mutResult;
}

async function proverEncodeEncrypt(value, encoder, encryptor) {
    const bitSizeFloat = 40;
    const plain = encoder.encode(Float64Array.from([value]), Math.pow(2, bitSizeFloat));
    const cipher = encryptor.encrypt(plain);
    return cipher;
}


module.exports = { studentMain, signatureVerify, generateEvaluator, computeResult, proverEncodeEncrypt };

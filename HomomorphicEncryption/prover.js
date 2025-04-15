const SEAL = require('node-seal');
const fs = require('fs');
const crypto = require("crypto");
const { subtle } = globalThis.crypto;

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
    // the following function calculates (cipher1 - cipher2)
    const subResult = evaluator.sub(cipher1, cipher2);
    const mutResult = evaluator.multiplyPlain(subResult, pRand);

    const proverResult = { result: mutResult.save() }
    fs.writeFileSync('./HomomorphicEncryption/proverData.json', JSON.stringify(proverResult));

    return mutResult;
}

async function proverEncodeEncrypt(value, encoder, encryptor) {
    const bitSizeFloat = 40;
    const plain = encoder.encode(Float64Array.from([value]), Math.pow(2, bitSizeFloat));
    const cipher = encryptor.encrypt(plain);
    return cipher;
}

async function proverCalculate(timestamp, signPublicKey, signature, thresholdCiphertext, encoder, encryptor, evaluator) {
    let ver = await signatureVerify(signPublicKey, signature, thresholdCiphertext);
    if (ver) {
        let issuanceCiphertext = await proverEncodeEncrypt(timestamp, encoder, encryptor);
        let result = await computeResult(encoder, evaluator, thresholdCiphertext, issuanceCiphertext);
        return result;
    }
}

module.exports = { proverCalculate, signatureVerify, generateEvaluator, computeResult, proverEncodeEncrypt };

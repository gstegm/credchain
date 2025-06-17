const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const { subtle } = globalThis.crypto;
const assert = require('assert');


async function verifierSignatureVerify(pubKey, signature, data) {
    const ec = new TextEncoder();
    const verified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' }}, pubKey, signature, ec.encode(data));
    return verified;
}

async function verifierComputeResult(evaluator, cipher1, cipher2) {
    const compResult = tfhe_rs.lessThanEqual(cipher1, cipher2, evaluator);
    fs.writeFileSync('./HomomorphicEncryption/proverData.json', JSON.stringify(compResult));
    return compResult;
}

async function verifierEncryptPublicKey(value, publicKey) {
    if (typeof(value) == "boolean") {
        const cipher = await tfhe_rs.encryptBoolPublicKey(value, publicKey);
        return cipher;
    } else {
        const pValue = parseInt(value);
        const cipher = await tfhe_rs.encryptPublicKey(pValue, publicKey);
        return cipher;
    }
}

// https://stackoverflow.com/questions/4083204/secure-random-numbers-in-javascript
let random = ()=> crypto.getRandomValues(new Uint32Array(1))[0]/2**32;

async function verifierChoose(n, r) {
    assert (r <= n, "r should be smaller than n");
    // https://stackoverflow.com/questions/12987719/javascript-how-to-randomly-sample-items-without-replacement
    let chosen = [];
    for (let i=0;i<n;i++) {
        chosen.push(i);
    }
    for (let i=0; i<(n-r); i++) {
        let randomIndex = Math.floor(random()*chosen.length);
        chosen.splice(randomIndex, 1);
    }
    return chosen;
}

async function verifierCreateDecoys(evaluator, publicKey, thresholdPlaintext, issuanceCiphertext, n) {
    assert(n % 2 == 0, "n has to be an even integer")
    const decoyValueOrFlipped = [];
    const cipher = [];
    const computationIdxs = await verifierChoose(n, n/2);

    for (let i = 0; i < n; i++) {
        if (computationIdxs.includes(i)) {
            const thresholdCiphertext = await verifierEncryptPublicKey(thresholdPlaintext, publicKey);
            let compResult = await verifierComputeResult(evaluator, thresholdCiphertext, issuanceCiphertext);
            const flipBit = Boolean(Math.floor(random() * 2));
            if (flipBit) {
                compResult = tfhe_rs.flipBit(compResult, evaluator);
            }
            decoyValueOrFlipped.push(flipBit);
            cipher.push(compResult);
        } else {
            const decoyPlain = Boolean(Math.floor(random() * 2));
            const decoyCipher = await verifierEncryptPublicKey(decoyPlain, publicKey);
            decoyValueOrFlipped.push(decoyPlain);
            cipher.push(decoyCipher);
        }
    }
    return {cipher, decoyValueOrFlipped, computationIdxs};
}

async function verifierVerify(plain, decoyValueOrFlipped, computationIdxs, n) {
    let validCount = 0, invalidCount = 0;
    for (let i = 0; i < n; i++) {
        if (computationIdxs.includes(i) && !decoyValueOrFlipped[i]) {
            plain[i] ? validCount++ : invalidCount++;
        } else if (computationIdxs.includes(i) && decoyValueOrFlipped[i]) {
            !plain[i] ? validCount++ : invalidCount++;
        } else {
            assert(plain[i] === decoyValueOrFlipped[i], "tampered result");
        }
    }
    assert(validCount === n/2 || invalidCount === n/2, "tampered result");
    console.log(validCount === n/2 ? "\tVALID Issuance Date" : "\tINVALID Issuance Date");
    return validCount === n/2;
}

async function verifierCalculate(issuanceCiphertext, signPublicKey, signature, thresholdPlaintext, publicKey, evaluator, n) {
    let ver = await verifierSignatureVerify(signPublicKey, signature, issuanceCiphertext);
    if (ver) {
        let {cipher, decoyValueOrFlipped, computationIdxs} = await verifierCreateDecoys(evaluator, publicKey, thresholdPlaintext, issuanceCiphertext, n);
        return {cipher, decoyValueOrFlipped, computationIdxs};
    }
}

module.exports = { verifierComputeResult, verifierEncryptPublicKey, verifierCreateDecoys, verifierSignatureVerify, verifierVerify, verifierCalculate};
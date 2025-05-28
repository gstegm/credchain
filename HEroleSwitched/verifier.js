const tfhe_rs = require('../tfhe_comparison.node')
const fs = require('fs');
const { subtle } = globalThis.crypto;

// verify signed message sent by company with its public key (needed for alternative protocol)
async function verifierSignatureVerify(pubKey, signature, data) {
    const ec = new TextEncoder();
    const verified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' }}, pubKey, signature, ec.encode(data));
    return verified;
}

// needed for role-switched protocol
async function verifierComputeResult(evaluator, cipher1, cipher2) {
    const compResult = tfhe_rs.greaterThan(cipher1, cipher2, evaluator);
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
async function verifierCalculate(issuanceCiphertext, signPublicKey, signature, thresholdTimestamp, encryptor, evaluator) {
    let ver = await verifierSignatureVerify(signPublicKey, signature, issuanceCiphertext);
    if (ver) {
        //let thresholdCiphertext = await verifierEncryptPublicKey(thresholdTimestamp, encryptor);
        let {mixedListCipher, decoyListPlain, computationIdxs} = await verifierCreateDecoys(evaluator, encryptor, thresholdTimestamp, issuanceCiphertext);
        return {mixedListCipher, decoyListPlain, computationIdxs};
    }
}

module.exports = { verifierComputeResult, verifierEncryptPublicKey, verifierCreateDecoys, verifierSignatureVerify, verifierVerify, verifierCalculate};
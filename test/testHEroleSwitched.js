const { web3, assert, artifacts } = require("hardhat");
const { performance, PerformanceObserver } = require('perf_hooks');
const { generateEncryptionKeys, generateSignatureKeys, verifierEncrypt, verifierDecrypt, verifierSign, verifierComputeResult, verifierCreateDecoys, verifierEncryptPublicKey, verifierSignatureVerify, verifierVerify} = require("../HEroleSwitched/verifier.js");
const { proverGenerateEncryptionKeys, proverGenerateSignatureKeys, proverEncrypt, proverDecrypt, proverSign, signatureVerify, computeResult } = require("../HEroleSwitched/prover.js");

const DID = artifacts.require("DID");
const Cred = artifacts.require("Credentials");
const Admin = artifacts.require("AdminAccounts");
const Issuer = artifacts.require("IssuerRegistry");

const ArrowDown = '\u2193';

// Set up performance observer
const obs = new PerformanceObserver((items) => {
    console.log(`\tDuration: ${items.getEntries()[0].duration.toFixed(2)} ms ${ArrowDown}`);
    performance.clearMarks();
});
obs.observe({ entryTypes: ['measure'] });


describe("DID Registry", function() {
    let accounts;
    let holder;
    let issuer;
    let issuer_;

    // contract instances
    let adminRegistryInstance;
    let issuerRegistryInstance;
    let didRegistryInstance;
    let credRegistryInstance;

    before(async function() {
        accounts = await web3.eth.getAccounts();
        holder = accounts[1];
        // issuer = accounts[2];
        // create an account with public/private keys
        issuer_ = web3.eth.accounts.create();
        issuer_Pri = issuer_.privateKey;
        issuer = issuer_.address;
    });

    describe("Deployment", function() {
        it('Deploying the Admin registry contract', async() => {
            adminRegistryInstance = await Admin.new();
            await web3.eth.getBalance(adminRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract");
            });
        });

        it('Deploying the Issuers Registry contract', async() => {
            issuerRegistryInstance = await Issuer.new(adminRegistryInstance.address);
            await web3.eth.getBalance(issuerRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract");
            });
        });

        it('Deploying the DID Registry contract', async() => {
            didRegistryInstance = await DID.new();
            await web3.eth.getBalance(didRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract");
            });
        });

        it('Deploying the Credential Registry contract', async() => {
            credRegistryInstance = await Cred.new();
            await web3.eth.getBalance(credRegistryInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract");
            });
        });

        // it('Deploying and generating bitmap', async() => {
        //     subAccInstance = await SubAcc.new(issuerRegistryInstance.address /*, accInstance.address*/);
        //     await web3.eth.getBalance(subAccInstance.address).then((balance) => {
        //         assert.equal(balance, 0, "check balance of the contract");
        //     });

        //     // calculate how many hash functions needed and update in contract
        //     await initBitmap(subAccInstance, capacity);

        //     // clean up from previous tests
        //     emptyProducts();
        //     emptyStaticAccData();
        // });

        // it('Deploying and generating global accumulator', async() => {
        //     let [n, g] = gen();
        //     // when adding bytes to contract, need to concat with "0x"
        //     let nHex = "0x" + bigInt(n).toString(16); // convert back to bigInt with bigInt(nHex.slice(2), 16)
        //     let gHex = "0x" + bigInt(g).toString(16);

        //     accInstance = await Acc.new(issuerRegistryInstance.address, subAccInstance.address, gHex, nHex);
        //     await web3.eth.getBalance(accInstance.address).then((balance) => {
        //         assert.equal(balance, 0, "check balance of the contract");
        //     });
        // });
    });

    describe("Add issuer to the registry", function() {
        it('Adding issuer', async() => {
            await issuerRegistryInstance.addIssuer(issuer);
        });
    });

    describe("Identity Register", function() {
        it('Registering the identity with contract', async() => {
            let now = new Date();
            let ubaasDID = web3.utils.sha3(issuer + now);
            await didRegistryInstance.register(holder, ubaasDID);
            await didRegistryInstance.getInfo(holder).then((result) => {
                assert.exists(result[0], "check if did was generated");
            });
        });
    });

// ===================================================================================================================

    describe("Homomorphic encryption validation scenario", function() {
        const thresholdTimestamp = "1262304000";  // Unix timestamp: Fri Jan 01 2010 00:00:00
        const issuanceTimestamp = "1500000000";   // Unix timestamp: Fri Jul 14 2017 02:40:00
        let proverSignPublicKey, proverSignPrivateKey, proverSignature;
        let proverEncryptor, proverDecryptor, plain;
        let issuanceCiphertext;
        let cipher, decoyValueOrFlipped;

        it("(1) Prover parameters setup and (2) generates keys", async() => {
            let proverInstances = await proverGenerateEncryptionKeys();
            let signingKeys = await proverGenerateSignatureKeys();

            proverEncryptor = proverInstances.encryptor;
            proverDecryptor = proverInstances.decryptor;
            proverEvaluator = proverInstances.evaluator;
            proverSignPublicKey = signingKeys.publicKey;
            proverSignPrivateKey = signingKeys.privateKey;

            assert.exists(proverSignPublicKey, 'signing public key was not generated');
            assert.exists(proverSignPrivateKey, 'signing private key was not generated');
            assert.exists(proverEncryptor, "encryptor instance was not generated");
        });

        it("(3) Prover encrypts issuance timestamp", async() => {
            issuanceCiphertext = await proverEncrypt(issuanceTimestamp, proverEncryptor);
            assert.exists(issuanceCiphertext, 'issuance data was not encrypted');
        });

        it("(5) Prover signs ciphertext", async() => {
            proverSignature = await proverSign(proverSignPrivateKey, issuanceCiphertext);
            assert.exists(proverSignature, 'signature was not created');
        });

        it("(6) Prover sends the ciphertext, verification keys, signature to the verifier, simulating the delay", async() => {
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
        });

        it("(7) Verifier verifies signature on the ciphertext", async() => {
            await verifierSignatureVerify(proverSignPublicKey, proverSignature, issuanceCiphertext).then((ver) => {
                assert.isTrue(ver, "signature verification failed");
            });
        });

        it("(8-11) Verifier computes the difference between threshold and issuance ciphers", async() => {
            ({cipher, decoyValueOrFlipped, computationIdxs} = await verifierCreateDecoys(proverEvaluator, proverEncryptor, thresholdTimestamp, issuanceCiphertext, 10));
            assert.exists(cipher, 'result was not computed');
            assert.exists(decoyValueOrFlipped, 'result was not computed');
            assert.exists(computationIdxs, 'result was not computed');
        });

        it("(12) Verifier sends the results to the prover", async() => {
            // Simulate user sending to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
        });

        it("(13) Prover decrypts result", async() => {
            plain = await proverDecrypt(cipher, proverDecryptor);
        });

        it("(14) Prover sends decrypted result to verifier", async() => {
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
        });

        it("(15) Verifier verifies result", async() => {
            res = await verifierVerify(plain, decoyValueOrFlipped, computationIdxs, 10);
            assert.isTrue(res, 'the issuance date invalid')
        });
    });

    describe("Homomorphic encryption time measurements", function() {

        it("A complete sequence of HE; issuance date valid", async() => {
            const thresholdTimestamp = "1262304000";  // Unix timestamp: Fri Jan 01 2010 00:00:00
            const issuanceTimestamp = "1500000000";   // Unix timestamp: Fri Jul 14 2017 02:40:00
            let proverSignPublicKey, proverSignPrivateKey, proverSignature;
            let proverEncryptor, proverDecryptor, plain;
            let issuanceCiphertext;
            let cipher, decoyValueOrFlipped;

            performance.mark("start");

            let proverInstances = await proverGenerateEncryptionKeys();
            let signingKeys = await proverGenerateSignatureKeys();

            proverEncryptor = proverInstances.encryptor;
            proverDecryptor = proverInstances.decryptor;
            proverEvaluator = proverInstances.evaluator;
            proverSignPublicKey = signingKeys.publicKey;
            proverSignPrivateKey = signingKeys.privateKey;

            issuanceCiphertext = await proverEncrypt(issuanceTimestamp, proverEncryptor);
            proverSignature = await proverSign(proverSignPrivateKey, issuanceCiphertext);

            let ver = await verifierSignatureVerify(proverSignPublicKey, proverSignature, issuanceCiphertext);

            if (ver) {
                ({cipher, decoyValueOrFlipped, computationIdxs} = await verifierCreateDecoys(proverEvaluator, proverEncryptor, thresholdTimestamp, issuanceCiphertext, 10));
                plain = await proverDecrypt(cipher, proverDecryptor);
                await verifierVerify(plain, decoyValueOrFlipped, computationIdxs, 10).then((res) => {
                    assert.isTrue(res, 'the issuance date invalid');
                })
            }

            performance.mark("end");
            performance.measure("HE", "start", "end");
        })
    });
});

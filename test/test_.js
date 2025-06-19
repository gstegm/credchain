const { web3, assert, artifacts } = require("hardhat");
const { performance, PerformanceObserver } = require('perf_hooks');
const { generateEncryptionKeys, generateSignatureKeys, verifierEncrypt, verifierDecrypt, verifierSign } = require("../HomomorphicEncryption/verifier.js");
const { signatureVerify, computeResult, proverEncrypt } = require("../HomomorphicEncryption/prover.js");

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
        let verifierSignPublicKey, verifierSignPrivateKey, verifierSignature;
        let verifierPublicKey, verifierClientKey;
        let proverEvaluator, proverResult;
        let thresholdCiphertext, issuanceCiphertext;

        it("(1) Verifier parameters setup and (2) generates keys", async() => {
            let verifierInstances = await generateEncryptionKeys();
            let signingKeys = await generateSignatureKeys();

            verifierPublicKey = verifierInstances.publicKey;
            verifierClientKey = verifierInstances.clientKey;
            proverEvaluator   = verifierInstances.evaluator;
            verifierSignPublicKey = signingKeys.publicKey;
            verifierSignPrivateKey = signingKeys.privateKey;

            assert.exists(verifierSignPublicKey, 'signing public key was not generated');
            assert.exists(verifierSignPrivateKey, 'signing private key was not generated');
            assert.exists(verifierPublicKey, "HE public key instance was not generated");
        });

        it("(3) Verifier encrypts threshold timestamp", async() => {
            thresholdCiphertext = await verifierEncrypt(thresholdTimestamp, verifierClientKey);
            assert.exists(thresholdCiphertext, 'theshold data was not encrypted');
        });

        it("(5) Verifier signs ciphertext", async() => {
            verifierSignature = await verifierSign(verifierSignPrivateKey, thresholdCiphertext);
            assert.exists(verifierSignature, 'signature was not created');
        });

        it("(6) Verifier sends the ciphertext, verification keys, signature to the prover, simulating the delay", async() => {
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
        });

        it("(7) Prover verifies signature on the siphertext", async() => {
            await signatureVerify(verifierSignPublicKey, verifierSignature, thresholdCiphertext).then((ver) => {
                assert.isTrue(ver, "signature verification failed");
            });
        });

        it("(8) Prover encrypts issuance timestamp", async() => {
            issuanceCiphertext = await proverEncrypt(issuanceTimestamp, verifierPublicKey);
            assert.exists(issuanceCiphertext, 'issuance data was not encrypted');
        });

        it("(9-11) Prover computes the difference between threshold and issuance ciphers", async() => {
            proverResult = await computeResult(proverEvaluator, thresholdCiphertext, issuanceCiphertext);
            assert.exists(proverResult, 'result was not computed');
        });

        it("(12) Prover sends the results to the verifier", async() => {
            // Simulate user sending to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
        });

        it("(13) Verifier decrypts result and verifies", async() => {
            await verifierDecrypt(proverResult, verifierClientKey).then((res) => {
                assert.isTrue(res, 'the issuance date invalid')
            });
        });
    });

    describe("Homomorphic encryption time measurements", function() {

        it("A complete sequence of HE; issuance date valid", async() => {
            const thresholdTimestamp = "1262304000";  // Unix timestamp: Fri Jan 01 2010 00:00:00
            const issuanceTimestamp = "1500000000";   // Unix timestamp: Fri Jul 14 2017 02:40:00
            let verifierSignPublicKey, verifierSignPrivateKey, verifierSignature;
            let verifierPublicKey, verifierClientKey;
            let proverEvaluator, proverResult;
            let thresholdCiphertext, issuanceCiphertext;

            performance.mark("start");

            let verifierInstances = await generateEncryptionKeys();
            let signingKeys = await generateSignatureKeys();

            verifierPublicKey = verifierInstances.publicKey;
            verifierClientKey = verifierInstances.clientKey;
            proverEvaluator   = verifierInstances.evaluator;

            verifierSignPublicKey = signingKeys.publicKey;
            verifierSignPrivateKey = signingKeys.privateKey;

            thresholdCiphertext = await verifierEncrypt(thresholdTimestamp, verifierClientKey);
            verifierSignature = await verifierSign(verifierSignPrivateKey, thresholdCiphertext);

            let ver = await signatureVerify(verifierSignPublicKey, verifierSignature, thresholdCiphertext);

            if (ver) {
                issuanceCiphertext = await proverEncrypt(issuanceTimestamp, verifierPublicKey);
                proverResult = await computeResult(proverEvaluator, thresholdCiphertext, issuanceCiphertext);
                await verifierDecrypt(proverResult, verifierClientKey).then((res) => {
                    assert.isTrue(res, 'the issuance date invalid');
                })
            }

            performance.mark("end");
            performance.measure("HE", "start", "end");
        })
    });
});
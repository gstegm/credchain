var bigInt = require("big-integer");

const { web3, assert, artifacts } = require("hardhat");
const { generateCredential } = require("../utilities/credential.js");
const { gen, hashToPrime } = require("../utilities/accumulator.js");
const { initBitmap, addToBitmap, getBitmapData, getStaticAccData, checkInclusionBitmap, checkInclusionGlobal } = require("../utilities/bitmap.js");
const { storeEpochPrimes } = require("../utilities/epoch.js");
const { emptyProducts, emptyStaticAccData } = require("../utilities/product.js");
const { studentMain } = require("../HomomorphicEncryption/student.js");
const { companyMain } = require("../HomomorphicEncryption/company.js");
const { verify } = require("../revocation/revocation.js");
const { performance, PerformanceObserver } = require('perf_hooks');
const { companySetup, generateSignatureKeys, verifierSign } = require("../HomomorphicEncryption/company.js");

// using the following approach for testing:
// https://hardhat.org/hardhat-runner/docs/other-guides/truffle-testing

const DID = artifacts.require("DID");
const Cred = artifacts.require("Credentials");
const Admin = artifacts.require("AdminAccounts");
const Issuer = artifacts.require("IssuerRegistry");
const SubAcc = artifacts.require("SubAccumulator");
const Acc = artifacts.require("Accumulator");

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
    let issuer_Pri;

    // bitmap capacity
    let capacity = 30; // up to uin256 max elements

    // contract instances
    let adminRegistryInstance;
    let issuerRegistryInstance;
    let didRegistryInstance;
    let credRegistryInstance;
    let subAccInstance;
    let accInstance;

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

        it('Deploying and generating bitmap', async() => {
            subAccInstance = await SubAcc.new(issuerRegistryInstance.address /*, accInstance.address*/);
            await web3.eth.getBalance(subAccInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract");
            });

            // calculate how many hash functions needed and update in contract
            await initBitmap(subAccInstance, capacity);

            // clean up from previous tests
            emptyProducts();
            emptyStaticAccData();
        });

        it('Deploying and generating global accumulator', async() => {
            let [n, g] = gen();
            // when adding bytes to contract, need to concat with "0x"
            let nHex = "0x" + bigInt(n).toString(16); // convert back to bigInt with bigInt(nHex.slice(2), 16)
            let gHex = "0x" + bigInt(g).toString(16);

            accInstance = await Acc.new(issuerRegistryInstance.address, subAccInstance.address, gHex, nHex);
            await web3.eth.getBalance(accInstance.address).then((balance) => {
                assert.equal(balance, 0, "check balance of the contract");
            });
        });
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

    describe("1) Credential issuance and homomorphic encryption for correct Issuance Timestamp", function() {
        let studentData, companySetupData, companySecretKey, proof, vk;
        let verifierSignPublicKey, verifierSignPrivateKey, verifierSignature;

        // Case: Issuance Date is larger than Threshold Date
        const degreeThresholdTimestamp = "1262304000";  // Unix timestamp: Fri Jan 01 2010 00:00:00
        const degreeIssuanceTimestamp = "1500000000";   // Unix timestamp: Fri Jul 14 2017 02:40:00

        it("Company setup of encryption parameters", async function() {
            performance.mark("StartCompany1");
            ({ companySetupData, companySecretKey } = await companySetup(degreeThresholdTimestamp));
            let ciphertext = companySetupData.cipherTextThreshold;
            // let signingKeys = await generateSignatureKeys();
            // verifierSignPrivateKey = signingKeys.privateKey;
            verifierSignPublicKey = companySetupData.signaturePublicKey;
            verifierSignature = companySetupData.ciphertextSignature;
            // verifierSignature = await verifierSign(verifierSignPrivateKey, ciphertext);
            performance.mark("EndCompany1");
            const HEmeasureCompany1 = performance.measure(
                "HEcompany1",
                "StartCompany1",
                "EndCompany1",
            );
        });

        it("Company sends the encrypted threshold date and encryption parameters to the Student", async function() {
            // Simulate user sending the proof and VK to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
            assert.isNotNull(companySetupData, "Encryption parameters should not be null when sent");
        });

        it("Student performs homomorphic calculation and sends it to verifier", async function() {
            performance.mark("StartUser1");
            studentData = await studentMain(degreeIssuanceTimestamp, companySetupData, verifierSignature, verifierSignPublicKey);
            performance.mark("EndUser1");
            const HEmeasureUser1 = performance.measure(
                "HEuser1",
                "StartUser1",
                "EndUser1",
            );

            assert.isNotNull(studentData, "Encryption parameters should not be null");
            assert.isNotNull(vk, "Verification key should not be null");
        });

        it("Student sends the encrypted result to the Company", async function() {
            // Simulate user sending the proof and VK to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
            assert.isNotNull(proof, "Encryption parameters should not be null when sent");
            assert.isNotNull(vk, "Verification key should not be null when sent");
        });

        it("* Company verifies the result and checks bitmap", async function() {
            performance.mark("StartVerifier1");
            const isVerified = await companyMain(studentData, companySetupData, companySecretKey);
            performance.mark("EndVerifier1");
            const HEmeasureVerifier1 = performance.measure(
                "HEverifier1",
                "StartVerifier1",
                "EndVerifier1",
            );

            // console.log('isVerified', isVerified)

            assert.isTrue(isVerified, "Degree Issuance Date should be valid");
        });
    });

    describe("2) Credential issuance and homomorphic encryption for invalid Issuance Timestamp", function() {
        let studentData, companySetupData, companySecretKey, proof, vk;
        let verifierSignPublicKey, verifierSignature;

        // Case: Issuance Date is smaller than Threshold Date
        const degreeThresholdTimestamp = "1262304000";  // Unix timestamp: Fri Jan 01 2010 00:00:00
        const degreeIssuanceTimestamp = "1000000000";   // Unix timestamp: Sun Sep 09 2001 01:46:40

        it("Company setup of encryption parameters", async function() {
            performance.mark("StartCompany2");
            ({ companySetupData, companySecretKey } = await companySetup(degreeThresholdTimestamp));
            let signingKeys = await generateSignatureKeys();
            verifierSignature = await verifierSign(signingKeys.privateKey, companySetupData.cipherTextThreshold);
            verifierSignPublicKey = signingKeys.publicKey;
            performance.mark("EndCompany2");
            const HEmeasureCompany2 = performance.measure(
                "HEcompany2",
                "StartCompany2",
                "EndCompany2",
            );
        });

        it("Company sends the encrypted threshold date and encryption parameters to the Student", async function() {
            // Simulate user sending the proof and VK to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
            assert.isNotNull(companySetupData, "Encryption parameters should not be null when sent");
        });

        it("Student performs homomorphic calculation and sends it to verifier", async function() {
            performance.mark("StartUser2");
            studentData = await studentMain(degreeIssuanceTimestamp, companySetupData, verifierSignature, verifierSignPublicKey);
            performance.mark("EndUser2");
            const HEmeasureUser2 = performance.measure(
                "HEuser2",
                "StartUser2",
                "EndUser2",
            );

            assert.isNotNull(studentData, "Encryption parameters should not be null");
            assert.isNotNull(vk, "Verification key should not be null");
        });

        it("Student sends the encrypted result to the Company", async function() {
            // Simulate user sending the proof and VK to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
            assert.isNotNull(proof, "Encryption parameters should not be null when sent");
            assert.isNotNull(vk, "Verification key should not be null when sent");
        });

        it("Company verifies the result", async function() {
            performance.mark("StartVerifier2");
            const isVerified = await companyMain(studentData, companySetupData, companySecretKey);
            performance.mark("EndVerifier2");
            const HEmeasureVerifier2 = performance.measure(
                "HEverifier2",
                "StartVerifier2",
                "EndVerifier2",
            );

            assert.isFalse(isVerified, "Degree Issuance Date should be invalid");
        });
    });


    describe("3) Credential issuance and homomorphic encryption for tampered Issuance Timestamp", function() {
        let studentData, companySetupData, companySecretKey, proof, vk;
        let verifierSignPublicKey, verifierSignature;

        // Case: Issuance Date is smaller than Threshold Date
        const degreeThresholdTimestamp = "1262304000";  // Unix timestamp: Fri Jan 01 2010 00:00:00
        const degreeIssuanceTimestamp = "1500000000";   // Unix timestamp: Sun Sep 09 2001 01:46:40

        it("Company setup of encryption parameters", async function() {
            performance.mark("StartCompany2");
            ({ companySetupData, companySecretKey } = await companySetup(degreeThresholdTimestamp));
            let signingKeys = await generateSignatureKeys();
            verifierSignature = await verifierSign(signingKeys.privateKey, companySetupData.cipherTextThreshold);
            verifierSignPublicKey = signingKeys.publicKey;
            performance.mark("EndCompany2");
            const HEmeasureCompany2 = performance.measure(
                "HEcompany2",
                "StartCompany2",
                "EndCompany2",
            );
        });

        it("Company sends the encrypted threshold date and encryption parameters to the Student", async function() {
            // Simulate user sending the proof and VK to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
            assert.isNotNull(companySetupData, "Encryption parameters should not be null when sent");
        });

        it("Student performs homomorphic calculation and sends it to verifier", async function() {
            performance.mark("StartUser2");
            studentData = await studentMain(degreeIssuanceTimestamp, companySetupData, verifierSignature, verifierSignPublicKey);
            performance.mark("EndUser2");
            const HEmeasureUser2 = performance.measure(
                "HEuser2",
                "StartUser2",
                "EndUser2",
            );

            assert.isNotNull(studentData, "Encryption parameters should not be null");
            assert.isNotNull(vk, "Verification key should not be null");
        });

        it("Student modifies the result of the calculation", async function() {
            studentData.cipherTextResult = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";  // Simulate new cipherTextResult
        });

        it("Student sends the tampered result to the Company", async function() {
            // Simulate user sending the proof and VK to the verifier, and avoid credential already exists error
            await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate network delay
            assert.isNotNull(proof, "Encryption parameters should not be null when sent");
            assert.isNotNull(vk, "Verification key should not be null when sent");
        });

        it("Company verifies the result and checks bitmap", async function() {
            performance.mark("StartVerifier2");
            const isVerified = await companyMain(studentData, companySetupData, companySecretKey);
            performance.mark("EndVerifier2");
            const HEmeasureVerifier2 = performance.measure(
                "HEverifier2",
                "StartVerifier2",
                "EndVerifier2",
            )
        });
    });

});
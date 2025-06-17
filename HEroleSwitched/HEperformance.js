const { verifierCalculate, verifierVerify } = require("./verifier.js");
const { proverSetUp, proverDecrypt } = require("./prover.js");
// const { companySetup } = require("./company");
const pidusage = require('pidusage');
const { performance, PerformanceObserver } = require('perf_hooks');
const fs = require('fs');
const { Parser } = require('json2csv');

const degreeThresholdTimestamp = 1262304000;  // Unix timestamp: Fri Jan 01 2010 00:00:00
const degreeIssuanceTimestamp = 1500000000;   // Unix timestamp: Fri Jul 14 2017 02:40:00

async function measureFunctionExecution(func, label, ...args) {
    performance.mark(`${label}-start`);
    const result = await func(...args);
    performance.mark(`${label}-end`);
    performance.measure(label, `${label}-start`, `${label}-end`);
    const { cpu, memory } = await pidusage(process.pid);
    const duration = performance.getEntriesByName(label)[0].duration;
    performance.clearMarks();
    performance.clearMeasures();
    return { cpu: Number(cpu.toFixed(2)), memory: Number((memory / 1024 / 1024).toFixed(2)), duration: Number(duration.toFixed(2)), result };
}

function calculateStats(values) {
    // Filter out zero values and count the zeros
    const nonZeroValues = values.filter(value => value !== 0);
    const zeroCount = values.length - nonZeroValues.length;
    if (nonZeroValues.length === 0) {
        return { avg: 0, max: 0, min: 0, zeroCount };
    }

    const avg = nonZeroValues.reduce((a, b) => a + b, 0) / nonZeroValues.length;
    const max = Math.max(...nonZeroValues);
    const min = Math.min(...nonZeroValues);

    return { avg: Number(avg.toFixed(2)), max: Number(max.toFixed(2)), min: Number(min.toFixed(2)), zeroCount };
}

async function HEperformance(runs) {
    console.log("Running Homomorphic Encryption Performance Test.")
    const obs = new PerformanceObserver(() => {});
    obs.observe({ entryTypes: ['measure'] });

    let proverSetUpStat = [];     // step 1: prover sets up params, encrypts, signs
    let verifierStat = [];            // step 2: verifier verifies sig, computes result
    let proverDecryptStat = [];    // step 3: prover decrypts the result
    let verifierVerifyStat = [];    // step 4: verifier proves the result

    for (let i = 0; i < runs; i++) {
        console.log(`Run ${i + 1}/${runs}:`);

        const generateProverSetUpStat = await measureFunctionExecution(
            proverSetUp,
            'proverSetUp',
            degreeIssuanceTimestamp
        );
        // remove result from statistics stack
        proverSetUpStat.push({cpu: generateProverSetUpStat.cpu, memory: generateProverSetUpStat.memory, duration: generateProverSetUpStat.duration});

        const generateVerifierStat = await measureFunctionExecution(
            verifierCalculate,
            'verifierCalculate',
            generateProverSetUpStat.result.issuanceCiphertext,
            generateProverSetUpStat.result.signPublicKey,
            generateProverSetUpStat.result.proverSignature,
            degreeThresholdTimestamp,
            generateProverSetUpStat.result.proverPublicKey,
            generateProverSetUpStat.result.verifierEvaluator,
            10,
        );
        verifierStat.push({cpu: generateVerifierStat.cpu, memory: generateVerifierStat.memory, duration: generateVerifierStat.duration});

        const generateProverDecryptStat = await measureFunctionExecution(
            proverDecrypt,
            'proverDecrypt',
            generateVerifierStat.result.cipher,
            generateProverSetUpStat.result.proverClientKey,
        );
        proverDecryptStat.push({cpu: generateProverDecryptStat.cpu, memory: generateProverDecryptStat.memory, duration: generateProverDecryptStat.duration});

        const generateVerifierVerifyStat = await measureFunctionExecution(
            verifierVerify,
            'verifierVerify',
            generateProverDecryptStat.result,
            generateVerifierStat.result.decoyValueOrFlipped, 
            generateVerifierStat.result.computationIdxs,
            10
        );
        verifierVerifyStat.push({cpu: generateVerifierVerifyStat.cpu, memory: generateVerifierVerifyStat.memory, duration: generateVerifierVerifyStat.duration});
    };

    // measure Step 1
    const proverSetUpCPU = proverSetUpStat.map(stat => stat.cpu);
    const proverSetUpMemory = proverSetUpStat.map(stat => stat.memory);
    const proverSetUpTime = proverSetUpStat.map(stat => stat.duration);

    // measure Step 2
    const verifierCPU = verifierStat.map(stat => stat.cpu);
    const verifierMemory =  verifierStat.map(stat => stat.memory);
    const verifierTime =  verifierStat.map(stat => stat.duration);

    // measure Step 3
    const proverDecryptCPU = proverDecryptStat.map(stat => stat.cpu);
    const proverDecryptMemory = proverDecryptStat.map(stat => stat.memory);
    const proverDecryptTime = proverDecryptStat.map(stat => stat.duration);

    // measure Step 4
    const verifierVerifyCPU = verifierVerifyStat.map(stat => stat.cpu);
    const verifierVerifyMemory = verifierVerifyStat.map(stat => stat.memory);
    const verifierVerifyTime = verifierVerifyStat.map(stat => stat.duration);


    const proverSetUpCPUStats = calculateStats(proverSetUpCPU);
    const proverSetUpMemoryStats = calculateStats(proverSetUpMemory);
    const proverSetUpTimeStats = calculateStats(proverSetUpTime);

    const verifierCPUStats = calculateStats(verifierCPU);
    const verifierMemoryStats = calculateStats(verifierMemory);
    const verifierTimeStats = calculateStats(verifierTime);

    const proverDecryptCPUStats = calculateStats(proverDecryptCPU);
    const proverDecryptMemoryStats = calculateStats(proverDecryptMemory);
    const proverDecryptTimeStats = calculateStats(proverDecryptTime);


    const verifierVerifyCPUStats = calculateStats(verifierVerifyCPU);
    const verifierVerifyMemoryStats = calculateStats(verifierVerifyMemory);
    const verifierVerifyTimeStats = calculateStats(verifierVerifyTime);

    console.log("\nProver Setup Stats:");
    console.log(`CPU:\n\tAvg: ${proverSetUpCPUStats.avg}%, Max: ${proverSetUpCPUStats.max}%, Min: ${proverSetUpCPUStats.min}%, ZEROs: ${proverSetUpCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${proverSetUpMemoryStats.avg}MB, Max: ${proverSetUpMemoryStats.max}MB, Min: ${proverSetUpMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${proverSetUpTimeStats.avg}ms, Max: ${proverSetUpTimeStats.max}ms, Min: ${proverSetUpTimeStats.min}ms`);

    console.log("\nVerifier Computation Stats:");
    console.log(`CPU:\n\tAvg: ${verifierCPUStats.avg}%, Max: ${verifierCPUStats.max}%, Min: ${verifierCPUStats.min}%, ZEROs: ${verifierCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${verifierMemoryStats.avg}MB, Max: ${verifierMemoryStats.max}MB, Min: ${verifierMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${verifierTimeStats.avg}ms, Max: ${verifierTimeStats.max}ms, Min: ${verifierTimeStats.min}ms`);

    console.log("\nProver Decryption Stats:");
    console.log(`CPU:\n\tAvg: ${proverDecryptCPUStats.avg}%, Max: ${proverDecryptCPUStats.max}%, Min: ${proverDecryptCPUStats.min}%, ZEROs: ${proverDecryptCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${proverDecryptMemoryStats.avg}MB, Max: ${proverDecryptMemoryStats.max}MB, Min: ${proverDecryptMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${proverDecryptTimeStats.avg}ms, Max: ${proverDecryptTimeStats.max}ms, Min: ${proverDecryptTimeStats.min}ms`);

    console.log("\nVerifier Verify Stats:");
    console.log(`CPU:\n\tAvg: ${verifierVerifyCPUStats.avg}%, Max: ${verifierVerifyCPUStats.max}%, Min: ${verifierVerifyCPUStats.min}%, ZEROs: ${verifierVerifyCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${verifierVerifyMemoryStats.avg}MB, Max: ${verifierVerifyMemoryStats.max}MB, Min: ${verifierVerifyMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${verifierVerifyTimeStats.avg}ms, Max: ${verifierVerifyTimeStats.max}ms, Min: ${verifierVerifyTimeStats.min}ms`);


    const csvData = [];
    for (let i = 0; i < runs; i++) {
        csvData.push({
            run: i + 1,
            proverSetUpCPU: proverSetUpCPU[i],
            proverSetUpMemory: proverSetUpMemory[i],
            proverSetUpTime: proverSetUpTime[i],
            verifierCPU: verifierCPU[i],
            verifierMemory: verifierMemory[i],
            verifierTime: verifierTime[i],
            proverDecryptCPU: proverDecryptCPU[i],
            proverDecryptMemory: proverDecryptMemory[i],
            proverDecryptTime: proverDecryptTime[i],
            verifierVerifyCPU: verifierVerifyCPU[i],
            verifierVerifyMemory: verifierVerifyMemory[i],
            verifierVerifyTime: verifierVerifyTime[i],
            // verifierCPUAverage: (proverSetUpCPU[i] + verifierVerifyCPU[i]) / 2,
            // proverCPUAverage:
        });
    };

    const fields = [
        'run',
        'proverSetUpCPU', 'proverSetUpMemory', 'proverSetUpTime',
        'verifierCPU', 'verifierMemory', 'verifierTime',
        'proverDecryptCPU', 'proverDecryptMemory', 'proverDecryptTime',
        'verifierVerifyCPU', 'verifierVerifyMemory', 'verifierVerifyTime'
    ];
    const json2csvParser = new Parser({ fields });
    const csv = json2csvParser.parse(csvData);

    fs.writeFileSync('./evaluation/HE_performance_data.csv', csv);
    console.log('Performance data saved to HE_performance_data.csv');
}

// HEperformance().catch(console.error);
module.exports = { HE_performance_role_switched: HEperformance };

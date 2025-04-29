const { verifierSetUp, verifierProve } = require("./verifier_comp.js");
const { proverCalculate } = require("./prover_comp.js");
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

    // let companySetupStats = [];
    // let studentMainStats = [];
    // let companyMainStats = [];

    let verifierSetUpStat = [];     // step 1: verifier sets up params, encrypts, signs
    let proverStat = [];            // step 2: prover verifies sig, computes result
    let verifierVerifyStat = [];    // step 3: verifier proves the result

    for (let i = 0; i < runs; i++) {
        console.log(`Run ${i + 1}/${runs}:`);

        const generateVerifierSetUpStat = await measureFunctionExecution(
            verifierSetUp,
            'verifierSetUp',
            degreeThresholdTimestamp
        );
        // remove result from statistics stack
        verifierSetUpStat.push({cpu: generateVerifierSetUpStat.cpu, memory: generateVerifierSetUpStat.memory, duration: generateVerifierSetUpStat.duration});

        const generateProverStat = await measureFunctionExecution(
            proverCalculate,
            'proverCalculate',
            degreeIssuanceTimestamp,
            generateVerifierSetUpStat.result.signPublicKey,
            generateVerifierSetUpStat.result.verifierSignature,
            generateVerifierSetUpStat.result.thresholdCiphertext,
            generateVerifierSetUpStat.result.verifierEncryptor,
            generateVerifierSetUpStat.result.proverEvaluator,
        );
        proverStat.push({cpu: generateProverStat.cpu, memory: generateProverStat.memory, duration: generateProverStat.duration});

        const generateVerifierVerifyStat = await measureFunctionExecution(
            verifierProve,
            'verifierProve',
            generateProverStat.result,
            generateVerifierSetUpStat.result.verifierDecryptor,
        );
        verifierVerifyStat.push({cpu: generateVerifierVerifyStat.cpu, memory: generateVerifierVerifyStat.memory, duration: generateVerifierVerifyStat.duration});
    };

    // measure Step 1
    const verifierSetUpCPU = verifierSetUpStat.map(stat => stat.cpu);
    const verifierSetUpMemory = verifierSetUpStat.map(stat => stat.memory);
    const verifierSetUpTime = verifierSetUpStat.map(stat => stat.duration);

    // measure Step 2
    const proverCPU = proverStat.map(stat => stat.cpu);
    const proverMemory =  proverStat.map(stat => stat.memory);
    const proverTime =  proverStat.map(stat => stat.duration);

    // measure Step 3
    const verifierVerifyCPU = verifierVerifyStat.map(stat => stat.cpu);
    const verifierVerifyMemory = verifierVerifyStat.map(stat => stat.memory);
    const verifierVerifyTime = verifierVerifyStat.map(stat => stat.duration);


    const verifierSetUpCPUStats = calculateStats(verifierSetUpCPU);
    const verifierSetUpMemoryStats = calculateStats(verifierSetUpMemory);
    const verifierSetUpTimeStats = calculateStats(verifierSetUpTime);

    const proverCPUStats = calculateStats(proverCPU);
    const proverMemoryStats = calculateStats(proverMemory);
    const proverTimeStats = calculateStats(proverTime);

    const verifierVerifyCPUStats = calculateStats(verifierVerifyCPU);
    const verifierVerifyMemoryStats = calculateStats(verifierVerifyMemory);
    const verifierVerifyTimeStats = calculateStats(verifierVerifyTime);

    console.log("\nVerifier Setup Stats:");
    console.log(`CPU:\n\tAvg: ${verifierSetUpCPUStats.avg}%, Max: ${verifierSetUpCPUStats.max}%, Min: ${verifierSetUpCPUStats.min}%, ZEROs: ${verifierSetUpCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${verifierSetUpMemoryStats.avg}MB, Max: ${verifierSetUpMemoryStats.max}MB, Min: ${verifierSetUpMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${verifierSetUpTimeStats.avg}ms, Max: ${verifierSetUpTimeStats.max}ms, Min: ${verifierSetUpTimeStats.min}ms`);

    console.log("\nProver Computation Stats:");
    console.log(`CPU:\n\tAvg: ${proverCPUStats.avg}%, Max: ${proverCPUStats.max}%, Min: ${proverCPUStats.min}%, ZEROs: ${proverCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${proverMemoryStats.avg}MB, Max: ${proverMemoryStats.max}MB, Min: ${proverMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${proverTimeStats.avg}ms, Max: ${proverTimeStats.max}ms, Min: ${proverTimeStats.min}ms`);

    console.log("\nVerifier Verify Stats:");
    console.log(`CPU:\n\tAvg: ${verifierVerifyCPUStats.avg}%, Max: ${verifierVerifyCPUStats.max}%, Min: ${verifierVerifyCPUStats.min}%, ZEROs: ${verifierVerifyCPUStats.zeroCount}`);
    console.log(`Memory:\n\tAvg: ${verifierVerifyMemoryStats.avg}MB, Max: ${verifierVerifyMemoryStats.max}MB, Min: ${verifierVerifyMemoryStats.min}MB`);
    console.log(`Duration:\n\tAvg: ${verifierVerifyTimeStats.avg}ms, Max: ${verifierVerifyTimeStats.max}ms, Min: ${verifierVerifyTimeStats.min}ms`);


    const csvData = [];
    for (let i = 0; i < runs; i++) {
        csvData.push({
            run: i + 1,
            verifierSetUpCPU: verifierSetUpCPU[i],
            verifierSetUpMemory: verifierSetUpMemory[i],
            verifierSetUpTime: verifierSetUpTime[i],
            proverCPU: proverCPU[i],
            proverMemory: proverMemory[i],
            proverTime: proverTime[i],
            verifierVerifyCPU: verifierVerifyCPU[i],
            verifierVerifyMemory: verifierVerifyMemory[i],
            verifierVerifyTime: verifierVerifyTime[i],
            // verifierCPUAverage: (verifierSetUpCPU[i] + verifierVerifyCPU[i]) / 2,
            // proverCPUAverage:
        });
    };

    const fields = [
        'run',
        'verifierSetUpCPU', 'verifierSetUpMemory', 'verifierSetUpTime',
        'proverCPU', 'proverMemory', 'proverTime',
        'verifierVerifyCPU', 'verifierVerifyMemory', 'verifierVerifyTime'
    ];
    const json2csvParser = new Parser({ fields });
    const csv = json2csvParser.parse(csvData);

    fs.writeFileSync('./evaluation/HE_performance_data.csv', csv);
    console.log('Performance data saved to HE_performance_data.csv');
}

// HEperformance().catch(console.error);
module.exports = { HE_performance: HEperformance };

const fs = require("fs");
const { randomBytes } = require("crypto");
const { assert } = require("console");
const { generateCode, generateAndSaveCode } = require("./generateCode");
const { stringToPaddedU32NBy16StringArray } = require("./utils");
const { toU8StringArray } = require("./utils");
const { toU32StringArray } = require("./utils");
const { searchForPlainTextInBase64 } = require('wtfprotocol-helpers');
const axios = require("axios");
const ethers = require("ethers");
const util = require("util");
const exec = util.promisify(require("child_process").exec); // wrapper for exec that allows async/await for its completion (https://stackoverflow.com/questions/30763496/how-to-promisify-nodes-child-process-exec-and-child-process-execfile-functions)


const twitterJWT = 'eyJraWQiOiJvYWdZIn0.eyJjcmVkcyI6IlByb3RvY29sV3RmIiwiYXVkIjoiZ25vc2lzIiwicmFuZCI6IlMzS1I3WGtfUkc3R0tBYlVHQ2JiNHQ4all1UkhLVmpnc0FTeFYwME9zY1UiLCJleHAiOiIxNjUxMzY1MjUzIn0'
const googleJWT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2MTY0OWU0NTAzMTUzODNmNmI5ZDUxMGI3Y2Q0ZTkyMjZjM2NkODgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiMjU0OTg0NTAwNTY2LTNxaXM1NG1vZmVnNWVkb2dhdWpycDhyYjdwYnA5cXRuLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMjU0OTg0NTAwNTY2LTNxaXM1NG1vZmVnNWVkb2dhdWpycDhyYjdwYnA5cXRuLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAwNzg3ODQ0NDczMTcyMjk4NTQzIiwiZW1haWwiOiJuYW5ha25paGFsQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoidDZqVl9BZ0FyTGpuLXFVSlN5bUxoZyIsIm5hbWUiOiJOYW5hayBOaWhhbCBLaGFsc2EiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUFUWEFKdzRnMVA3UFZUS2ZWUU1ldFdtUVgxQlNvWjlPWTRVUWtLcjdsTDQ9czk2LWMiLCJnaXZlbl9uYW1lIjoiTmFuYWsgTmloYWwiLCJmYW1pbHlfbmFtZSI6IktoYWxzYSIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjUxMzQ5MjczLCJleHAiOjE2NTEzNTI4NzMsImp0aSI6IjA3NTU4ODdlOTI3MzA1ZTY0Y2E4MWVhMzE3YjYxZGQxYWJjNWFiZjgifQ'

const circuitParams = {
    google : {
        blocks : Math.ceil(googleJWT.length / 64),// How many blocks of 512 bits are there, rounded up?
        subStart : '"sub":"',
        subMiddleLen : 21,
        subEnd : '"',
        expStart : '"exp":',
        expMiddleLen : 10,
        expEnd : ',',
        aud : '"aud":"254984500566-3qis54mofeg5edogaujrp8rb7pbp9qtn.apps.googleusercontent.com"',
        headerLenB64 : 102
    },
    // Not used:
    twitter: {
        blocks : Math.ceil(twitterJWT.length / 64),// How many blocks of 512 bits are there, rounded up?
        subStart : '"creds":"',
        subMiddleLen : 11,
        subEnd : '"',
        expStart : '"exp":"',
        expMiddleLen : 10,
        expEnd : '"',
        aud : '"aud":"gnosis"',
        headerLenB64 : 19
    }
}

console.error("WARNING Please remember to check JWT signature against google jwks in sub oracle; I don't think that is currently checked. Do not deploy until that is checked");
/* @param {jwt} base64-encoded jwt
   @returns {subParams}, consisting of format
   {
    input: "abc123456789", // sub claim's value
    key: "43ed707f926d4c924f8cf5430beb8e70d8f9633c221fcabe6a4eb09862794fb4e424d08ab5a20863920591", // deterministically generated key based on sub claim and oracle's secret key
    hashed: "733181da32e727b8507a47d57571d2ae9d4f43d3c86cc758ff2d1dd45875a282" // blake2s digest of concat(input + key). this may be changed from blake2s another quantum-resistant and length-extension-resistant function
    }
 */

// For testing purposes, so we can test with expired JWTs (getSubParams will fail as it uses production server which will reject requests with JWTs)
function getSubParamsTesting(jwtType){
    if (jwtType == "google") {
        return {
            input: "100787844473172298543",
            key: "43ed707f926d4c924f8cf5430beb8e70d8f9633c221fcabe6a4eb09862794fb4e424d08ab5a20863920591",
            hashed: "733181da32e727b8507a47d57571d2ae9d4f43d3c86cc758ff2d1dd45875a282"
        }
    } else if (jwtType == "twitter") {
        return {
            input: "ProtocolWtf",
            key: "d05bfc1feaa3e042600482b51d73914c44d37a40b40d0633170c40d77ea818ca25ead4c004d0b08d2e21b3736d35d364775c096610",
            hashed: "51865586b53355f1bb12a8b989746d333093b7b4abc112645de89998f3d76a4d"
        }
    }
    
}
async function getSubParams(jwtType, jwt) {
    return await axios.post("https://oracle.holonym.link/subCommitment", {
        jwt : jwt
    }).data;
    
}

// @param {jwtType} "google" or "twitter"
// @param {jwt} JWT, base64-encoded
// @param {address} submitter's wallet addres
async function getProofParams(jwtType, jwt, address) {
    const cp = circuitParams[jwtType];
    assert(cp);
    const [header, payload, signature] = jwt.split(".");

                                                                         // ZoKrates likes string formats
    const subIdx = (searchForPlainTextInBase64(cp.subStart, payload)[0]) .toString();
    const expIdx = (searchForPlainTextInBase64(cp.expStart, payload)[0]) .toString();
    const audIdx = (searchForPlainTextInBase64(cp.aud,      payload)[0]) .toString();
    
    // const subParams = 
    console.log("env: ", process.env.NODE_ENV)
    const subParams = (process.env.NODE_ENV == "development") ? await getSubParamsTesting(jwtType) : await getSubParams(jwtType, jwt); 
    const [subCommitment, subSecret] = [toU32StringArray(Buffer.from(subParams.hashed, "hex")), toU8StringArray(Buffer.from(subParams.key, "hex"))];
    
    const tbs = `${header}.${payload}`;
    const paddedJwt = stringToPaddedU32NBy16StringArray(tbs);
    const digest = toU32StringArray(
        Buffer.from(
            ethers.utils.sha256(Buffer.from(tbs)).replace("0x",""),
            "hex"
        )
    );

    const expGreaterThan = process.env.NODE_ENV == "development" ? "1641020400" : Math.floor(Date.now()/1000).toString();

    const inputs = [
        paddedJwt, 
        digest, 
        subCommitment, 
        subSecret, 
        subIdx, 
        audIdx, 
        expGreaterThan, 
        expIdx,
        toU8StringArray(Buffer.from(address.replace("0x",""), "hex"))
    ];

    const [ circuitID, code ] = generateCode(cp);

    return [ circuitID, inputs ]
}

// @param {jwtType} "google" or "twitter"
// @param {jwt} JWT, base64-encoded
// @param {address} submitter's wallet addres
async function proveJWT(jwtType, jwt, address){
    // Check user has paid
    console.error("WARNING: No function implemented to check the user has paid for recovery -- DDOS attacks are possible");
    
    const [ circuitID, inputs ] = await getProofParams(jwtType, jwt, address);
    const start = Date.now();
    const output = await generateProofCLI(circuitID, inputs);
    console.log(`proof generation took ${(Date.now()-start)/1000}s`);
    return JSON.stringify(output);
}

async function generateProofCLI(circuitID, inputs) {
    const cliArgs = argsToCLIArgs(inputs);
    // Create a temporary name for current tasks to be deleted once CLI execution is done:
    const tmpValue = randomBytes(16).toString("hex");
    const binaryPath = `compiled/${circuitID}.out`;
    const provingKeyPath = `pvkeys/${circuitID}.proving.key`;
    const tmpWitnessPath = `tmp/${tmpValue}.${circuitID}.witness`;
    const tmpProofPath = `tmp/${tmpValue}.${circuitID}.proof.json`;

    // Execute the command
    try {
        const {stdout, stderr} = await exec(`zokrates compute-witness -i ${binaryPath} -o ${tmpWitnessPath} -a ${cliArgs}; zokrates generate-proof -i ${binaryPath} -w ${tmpWitnessPath} -j ${tmpProofPath} -p ${provingKeyPath}; rm ${tmpWitnessPath}`);
        console.log(stdout)
        console.error(stderr)
    } catch(e) {
        console.error(e);
    }

    // Read the proof file, then delete it, then return it
    const retval = JSON.parse(fs.readFileSync(tmpProofPath));
    exec(`rm ${tmpProofPath}`);
    return retval;
}

// To convert zokrates-js args to zokrates-cli args
function argsToCLIArgs (args) {
    return args.map(x=>JSON.stringify(x))
    .join(``)
    .replace(/\"|,|\[|\]/g, ` `)
    .replace(/\s+/g, ` `)
}

module.exports = {
    proveJWT : proveJWT
}

// To generate a new proof:
// proveJWT("google", googleJWT, "0xC8834C1FcF0Df6623Fc8C8eD25064A4148D99388").then(x=>console.log(x));
// Example valid proof:
// {"scheme":"g16","curve":"bn128","proof":{"a":["0x15c23df4b16a3dd2b7913a392ab065c7d3c959a67df3b8ae7dcc74d9c865fab3","0x1bbf681720fadcf21afce81aaeb368b8284e331461e5d495794ab0611fa9a876"],"b":[["0x0c4eeafb8e53c318b09caf214302c0bbcac8f8102797d3dc4ecdf10e7e756b9b","0x08526d7805fa3694433776cdde3da92e121e3573575da50a2bfc4afb7101ae84"],["0x2f232bbede4c1cb20855a450abac6f66b2ab0c619c4f6f4c841a5d9fb5fbc84d","0x2a1c4aa8d1233df9567eada71c2944698a7863bd6514ec2aa3881666aa5949ba"]],"c":["0x177927cc249e180ac27862069b80eda03e0742c73ef8bb6f9a736d8ea376d4f0","0x06135535f2581cfdf819ab3201eba64fc5ff9302bd18071564e313c0122bc4de"]},"inputs":["0x00000000000000000000000000000000000000000000000000000000236b413b","0x00000000000000000000000000000000000000000000000000000000f1f098d9","0x00000000000000000000000000000000000000000000000000000000ac2a4a1c","0x00000000000000000000000000000000000000000000000000000000adbc08b7","0x00000000000000000000000000000000000000000000000000000000d8aadb6e","0x00000000000000000000000000000000000000000000000000000000c048646b","0x0000000000000000000000000000000000000000000000000000000026bc6c2f","0x0000000000000000000000000000000000000000000000000000000001250576","0x00000000000000000000000000000000000000000000000000000000733181da","0x0000000000000000000000000000000000000000000000000000000032e727b8","0x00000000000000000000000000000000000000000000000000000000507a47d5","0x000000000000000000000000000000000000000000000000000000007571d2ae","0x000000000000000000000000000000000000000000000000000000009d4f43d3","0x00000000000000000000000000000000000000000000000000000000c86cc758","0x00000000000000000000000000000000000000000000000000000000ff2d1dd4","0x000000000000000000000000000000000000000000000000000000005875a282","0x0000000000000000000000000000000000000000000000000000000061cffbf0","0x00000000000000000000000000000000000000000000000000000000000000c8","0x0000000000000000000000000000000000000000000000000000000000000083","0x000000000000000000000000000000000000000000000000000000000000004c","0x000000000000000000000000000000000000000000000000000000000000001f","0x00000000000000000000000000000000000000000000000000000000000000cf","0x000000000000000000000000000000000000000000000000000000000000000d","0x00000000000000000000000000000000000000000000000000000000000000f6","0x0000000000000000000000000000000000000000000000000000000000000062","0x000000000000000000000000000000000000000000000000000000000000003f","0x00000000000000000000000000000000000000000000000000000000000000c8","0x00000000000000000000000000000000000000000000000000000000000000c8","0x00000000000000000000000000000000000000000000000000000000000000ed","0x0000000000000000000000000000000000000000000000000000000000000025","0x0000000000000000000000000000000000000000000000000000000000000006","0x000000000000000000000000000000000000000000000000000000000000004a","0x0000000000000000000000000000000000000000000000000000000000000041","0x0000000000000000000000000000000000000000000000000000000000000048","0x00000000000000000000000000000000000000000000000000000000000000d9","0x0000000000000000000000000000000000000000000000000000000000000093","0x0000000000000000000000000000000000000000000000000000000000000088","0x0000000000000000000000000000000000000000000000000000000000000001"]}
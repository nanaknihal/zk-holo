const fs = require("fs");
const { randomBytes } = require("crypto");
const { assert } = require("console");
const { generateCircuit, generateAndSaveCircuit } = require("./generateCircuit");
const { stringToPaddedU32NBy16StringArray } = require("./utils");
const { toU8StringArray } = require("./utils");
const { toU32StringArray } = require("./utils");
const { searchForPlainTextInBase64 } = require('wtfprotocol-helpers');
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
async function getSubParams(jwt) {
    const payloadJSON = JSON.parse(Buffer.from(jwt.split(".")[1], "base64"));
    return await axios.post("https://recovery.holonym.id/subkeyoracle", {
        sub : payloadJSON.sub
    });
    
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
    
    const subParams = await getSubParams(jwt);
    const [subCommitment, subSecret] = [toU32StringArray(Buffer.from(subParams.hashed, "hex")), toU8StringArray(Buffer.from(subParams.key, "hex"))];
    
    const tbs = `${header}.${payload}`;
    const paddedJwt = stringToPaddedU32NBy16StringArray(tbs);
    const digest = toU32StringArray(
        Buffer.from(
            ethers.utils.sha256(Buffer.from(tbs)).replace("0x",""),
            "hex"
        )
    );

    const expGreaterThan = (Date.now()/1000).toString();

    const inputs = [
        paddedJwt, 
        digest, 
        subCommitment, 
        subSecret, 
        subIdx, 
        audIdx, 
        expGreaterThan, 
        expIdx,
        address
    ];

    const [ circuitID, code ] = generateCircuit(cp); // Should be renamed to generateCode as it's not quite generating a circuit

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
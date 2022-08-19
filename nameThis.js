const { initialize } = require("zokrates-js");
const fs = require("fs");
const path = require("path");
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


const compileOptions = {
    location: "jsVersion.zok", // location of the root module
    resolveCallback: (from, to) => {
        console.log(from + ' is importing ' + to);
        const location = path.resolve(path.dirname(path.resolve(from)), to + '.zok');
        const source = fs.readFileSync(location).toString();
        return { source, location };
    }
};


// const jwt = 'eyJraWQiOiJvYWdZIn0.eyJjcmVkcyI6IlByb3RvY29sV3RmIiwiYXVkIjoiZ25vc2lzIiwicmFuZCI6IlMzS1I3WGtfUkc3R0tBYlVHQ2JiNHQ4all1UkhLVmpnc0FTeFYwME9zY1UiLCJleHAiOiIxNjUxMzY1MjUzIn0'
const jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2MTY0OWU0NTAzMTUzODNmNmI5ZDUxMGI3Y2Q0ZTkyMjZjM2NkODgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiMjU0OTg0NTAwNTY2LTNxaXM1NG1vZmVnNWVkb2dhdWpycDhyYjdwYnA5cXRuLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMjU0OTg0NTAwNTY2LTNxaXM1NG1vZmVnNWVkb2dhdWpycDhyYjdwYnA5cXRuLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAwNzg3ODQ0NDczMTcyMjk4NTQzIiwiZW1haWwiOiJuYW5ha25paGFsQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoidDZqVl9BZ0FyTGpuLXFVSlN5bUxoZyIsIm5hbWUiOiJOYW5hayBOaWhhbCBLaGFsc2EiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUFUWEFKdzRnMVA3UFZUS2ZWUU1ldFdtUVgxQlNvWjlPWTRVUWtLcjdsTDQ9czk2LWMiLCJnaXZlbl9uYW1lIjoiTmFuYWsgTmloYWwiLCJmYW1pbHlfbmFtZSI6IktoYWxzYSIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjUxMzQ5MjczLCJleHAiOjE2NTEzNTI4NzMsImp0aSI6IjA3NTU4ODdlOTI3MzA1ZTY0Y2E4MWVhMzE3YjYxZGQxYWJjNWFiZjgif'
const [header, payload, signature] = jwt.split(".");
const circuitParams = {
    blocks : Math.ceil(jwt.length / 64),// How many blocks of 512 bits are there, rounded up?
    subStart : '"sub":"',
    // subStart : '"creds":"',
    subMiddleLen : 21,
    // subMiddleLen : 11,
    subEnd : '"',
    // expStart : '"exp":"',
    expStart : '"exp":',
    expMiddleLen : 10,
    expEnd : ',',
    // expEnd : '"',
    aud : '"aud":"254984500566-3qis54mofeg5edogaujrp8rb7pbp9qtn.apps.googleusercontent.com"',
    // aud : '"aud":"gnosis"',
    // shiftB64 : (4 - ((header.length + 1) % 4) % 4)// Either 0, 1, 2, or 3 -- shifts the bits of the b64-decoded jwt by shiftB64 by adding 0, 1, 2, or 3 padding characters before decoding the jwt 
    headerLenB64 : 102
}


// Paylod offset in plaintext = header length (converted to plaintext, so 3/4 the length) + 1 for period
// const payloadOffset = Math.ceil((header.length + 1)* 3 / 4);
                                                                                                // Zokrates likes string formats
const subIdx = (/*payloadOffset + */searchForPlainTextInBase64(circuitParams.subStart, payload)[0]) .toString();
const expIdx = (/*payloadOffset + */searchForPlainTextInBase64(circuitParams.expStart, payload)[0]) .toString();
const audIdx = (/*payloadOffset + */searchForPlainTextInBase64(circuitParams.aud,      payload)[0]) .toString();

// This should be replaced with a call to the subSecretOracle with the JWT as proof that we are allowed to obtain the subSecret
const getSubParams = (jwt) => {
    // return {
    //     input: "ProtocolWtf",
    //     key: "d05bfc1feaa3e042600482b51d73914c44d37a40b40d0633170c40d77ea818ca25ead4c004d0b08d2e21b3736d35d364775c096610",
    //     hashed: "51865586b53355f1bb12a8b989746d333093b7b4abc112645de89998f3d76a4d"
    // }
    return {
        input: "100787844473172298543",
        key: "43ed707f926d4c924f8cf5430beb8e70d8f9633c221fcabe6a4eb09862794fb4e424d08ab5a20863920591",
        hashed: "733181da32e727b8507a47d57571d2ae9d4f43d3c86cc758ff2d1dd45875a282"
    }
    
}
const subParams = getSubParams(jwt);
const [subCommitment, subSecret] = [toU32StringArray(Buffer.from(subParams.hashed, "hex")), toU8StringArray(Buffer.from(subParams.key, "hex"))];
const tbs = `${header}.${payload}`;
const paddedJwt = stringToPaddedU32NBy16StringArray(tbs);
const digest = toU32StringArray(
    Buffer.from(
        ethers.utils.sha256(Buffer.from(tbs)).replace("0x",""),
        "hex"
    )
);
// const expGreaterThan = "1651365252";
const expGreaterThan = "1651352872";
const address = toU8StringArray(Buffer.from("abcdef12345678909876"))
initialize().then((zokratesProvider) => {

    const [ circuitID, code ] = generateCircuit(circuitParams);
    a = generateAndSaveCircuit(circuitParams);

    // compilation
    // const artifacts = zokratesProvider.compile(code, compileOptions);
    // console.log('done compiling')
    
    // computation
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
    ]

    console.log("Inputs:", inputs);

    // const { witness, output } = zokratesProvider.computeWitness(artifacts, inputs);
    // const parsedOut = Buffer.concat(JSON.parse(output).map(x=>Buffer.from(x.replace("0x",""), "hex")))

    // run setup
    // const keypair = zokratesProvider.setup(artifacts.program);
    const start = Date.now()
    console.log(start)
    // // generate proof
    // const proof = zokratesProvider.generateProof(artifacts.program, witness);
    
    generateProofCLI(circuitID, inputs).then(x=>{console.log(x); console.log(Date.now());console.log("proof generation took", (Date.now()-start)/1000, "s")});
    


});

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
    return retval
}

// To convert zokrates-js args to zokrates-cli args
function argsToCLIArgs (args) {
    return args.map(x=>JSON.stringify(x))
    .join(``)
    .replace(/\"|,|\[|\]/g, ` `)
    .replace(/\s+/g, ` `)
}
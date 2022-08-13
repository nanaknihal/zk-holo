const { initialize } = require("zokrates-js");
const fs = require("fs");
const path = require("path");
const { assert } = require("console");
const { generateCircuit, generateAndSaveCircuit } = require("./generateCircuit");
const { stringToPaddedU32NBy16StringArray } = require("./utils");
const { toU8StringArray } = require("./utils");
const { toU32StringArray } = require("./utils");
const { searchForPlainTextInBase64 } = require('wtfprotocol-helpers');
const ethers = require("ethers");

const compileOptions = {
    location: "jsVersion.zok", // location of the root module
    resolveCallback: (from, to) => {
        console.log(from + ' is importing ' + to);
        const location = path.resolve(path.dirname(path.resolve(from)), to + '.zok');
        const source = fs.readFileSync(location).toString();
        return { source, location };
    }
};


const jwt = 'eyJraWQiOiJvYWdZIn0.eyJjcmVkcyI6IlByb3RvY29sV3RmIiwiYXVkIjoiZ25vc2lzIiwicmFuZCI6IlMzS1I3WGtfUkc3R0tBYlVHQ2JiNHQ4all1UkhLVmpnc0FTeFYwME9zY1UiLCJleHAiOiIxNjUxMzY1MjUzIn0'
const circuitParams = {
    blocks : Math.ceil(jwt.length / 64),// How many blocks of 512 bits are there, rounded up?
    subStart : '"creds":"',
    subMiddleLen : 11,
    subEnd : '"',
    expStart : '"exp":"',
    expMiddleLen : 10,
    expEnd : '"',
    aud : '"aud":"gnosis"',
    shiftB64 : 0 // Either 0, 1, 2, or 3 -- shifts the bits of the b64-decoded jwt by shiftB64 by adding 0, 1, 2, or 3 padding characters before decoding the jwt 
}

const [header, payload, signature] = jwt.split(".");
// Paylod offset in plaintext = header length (converted to plaintext, so 3/4 the length) + 1 for period
const payloadOffset = Math.ceil((header.length + 1)* 3 / 4);
                                                                                                // Zokrates likes string formats
const subIdx = (payloadOffset + searchForPlainTextInBase64(circuitParams.subStart, payload)[0]) .toString();
const expIdx = (payloadOffset + searchForPlainTextInBase64(circuitParams.expStart, payload)[0]) .toString();
const audIdx = (payloadOffset + searchForPlainTextInBase64(circuitParams.aud,      payload)[0]) .toString();

// This should be replaced with a call to the subSecretOracle with the JWT as proof that we are allowed to obtain the subSecret
const getSubParams = (jwt) => {
    return {
        input: "ProtocolWtf",
        key: "d05bfc1feaa3e042600482b51d73914c44d37a40b40d0633170c40d77ea818ca25ead4c004d0b08d2e21b3736d35d364775c096610",
        hashed: "51865586b53355f1bb12a8b989746d333093b7b4abc112645de89998f3d76a4d"
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
const expGreaterThan = "1651365252";

initialize().then((zokratesProvider) => {

    const [ circuitID, code ] = generateCircuit(circuitParams);
    // a = generateAndSaveCircuit(circuitParams);
    console.log('code is')
    console.log(code)

    // compilation
    const artifacts = zokratesProvider.compile(code, compileOptions);

    console.log('done compiling')
    
    // computation
    const inputs = [
        paddedJwt, 
        digest, 
        subCommitment, 
        subSecret, 
        subIdx, 
        audIdx, 
        expGreaterThan, 
        expIdx
    ]
    const cliInputs = argsToCLIArgs(inputs);

    console.log("Inputs:", inputs);
    console.log("CLIInputs", cliInputs);

    const { witness, output } = zokratesProvider.computeWitness(artifacts, inputs);
    // const parsedOut = Buffer.concat(JSON.parse(output).map(x=>Buffer.from(x.replace("0x",""), "hex")))

    // run setup
    // const keypair = zokratesProvider.setup(artifacts.program);
    // const start = Date.now()
    // // generate proof
    // const proof = zokratesProvider.generateProof(artifacts.program, witness);
    // console.log("proof generation took", (Date.now()-start)/1000, "s")
    


});

// To convert zokrates-js args to zokrates-cli args
function argsToCLIArgs (args) {
    return args.map(x=>JSON.stringify(x))
    .join(``)
    .replace(/\"|,|\[|\]/g, ` `)
    .replace(/\s+/g, ` `)
}
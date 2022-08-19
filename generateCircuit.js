const { exec } = require("child_process");
const {assert} = require("console");
const fs = require("fs");

// Example circuitParams:
/* 
const circuitParams = {
    blocks : Math.ceil(jwt.length / 64),// How many blocks of 512 bits are there, rounded up?
    subStart : '"creds":"',
    subMiddleLen : 11,
    subEnd : '"',
    expStart : '"exp":"',
    expMiddleLen : 10,
    expEnd : '"',
    aud : '"aud":"gnosis"',
    headerLenB64 : 19
}
*/


function generateCircuit(circuitParams){
  // A paramstring is used as a UUID for a circuit. Thus, a circuit can be generated with circuitParams and can be named ${paramString} so it is clear exactly what the circuit does
  const paramString = Buffer.from(Object.values(circuitParams).join("_")).toString("base64");

  // May be helpful later when trying to read the correct proving key:
  // try {
  //     const provingKey = fs.readFileSync(`${paramString}.proving.key`);
  // } catch(e) {
  //     console.error("could not find a proving key for circuit with params", circuitParams);
  // }

  // assert([0,1,2,3].includes(circuitParams.shiftB64))
  assert(circuitParams.subStart.length + circuitParams.subMiddleLen + circuitParams.subEnd.length <= 48) // Ensure there is enough room for a 16-byte subSecret

  const constants = `
  const u32 SUB_START_LENGTH = ${circuitParams.subStart.length};
  const u32 SUB_END_LENGTH = ${circuitParams.subEnd.length};
  const u32 SUB_MIDDLE_LENGTH = ${circuitParams.subMiddleLen};
  const u32 SUB_LENGTH = SUB_START_LENGTH + SUB_END_LENGTH + SUB_MIDDLE_LENGTH;
  const u32 SUB_SECRET_LENGTH = 64 - SUB_MIDDLE_LENGTH; // Length of sub claim, including SUB_START and SUB_END. SHOULD NOT BE LESS THAN 16 BYTES FOR SECURE RANDOMNESS

  const u8[SUB_START_LENGTH] SUB_START = [ ${Buffer.from(circuitParams.subStart).join(', ')} ]; 
  const u8[SUB_END_LENGTH] SUB_END = [ ${Buffer.from(circuitParams.subEnd).join(', ')} ];

  const u32 EXP_START_LENGTH = ${circuitParams.expStart.length};
  const u32 EXP_END_LENGTH = ${circuitParams.expEnd.length};
  const u32 EXP_MIDDLE_LENGTH = ${circuitParams.expMiddleLen};
  const u32 EXP_LENGTH = EXP_START_LENGTH + EXP_END_LENGTH + EXP_MIDDLE_LENGTH; 

  const u8[EXP_START_LENGTH] EXP_START = [ ${Buffer.from(circuitParams.expStart).join(', ')} ];
  const u8[EXP_END_LENGTH] EXP_END = [ ${Buffer.from(circuitParams.expEnd).join(', ')} ];

  const u32 AUD_LENGTH = ${circuitParams.aud.length};
  const u8[AUD_LENGTH] AUD = [ ${Buffer.from(circuitParams.aud).join(', ')} ];

  const u32 JWT_BLOCKS = ${circuitParams.blocks}; // represents length of padded JWT (base64 JWT with periods, header and payload, no signature) in 512-byte multiples 
  const u32 JWT_LENGTH_BASE64 = JWT_BLOCKS * 64;
  const u32 HEADER_LENGTH_BASE64 = ${circuitParams.headerLenB64}; // how long is eyJh... (excluding the period)
  const u32 PAYLOAD_LENGTH_BASE64_ = JWT_LENGTH_BASE64 - HEADER_LENGTH_BASE64 - 1; // 1 for . between payload and header
  const u32 PAYLOAD_BASE64_REMAINDER = PAYLOAD_LENGTH_BASE64_ % 4;
  const u32 PAYLOAD_LENGTH_BASE64 = PAYLOAD_LENGTH_BASE64_ - PAYLOAD_BASE64_REMAINDER; // Floor when divided by 4 so it's a valid base64 length
  const u32 PAYLOAD_LENGTH_PLAINTEXT = PAYLOAD_LENGTH_BASE64 * 3 / 4;

  `
  //
  const source = `
  from "../base64" import fromBase64;
  from "../utils" import decimalStringToField, unflatten, flatten, substringAt, bool_array_to_u8_array, u8_array_to_bool_array;
  from "EMBED" import u32_to_bits as u32ToBits;
  from "EMBED" import u32_from_bits as u32FromBits;
  from "EMBED" import u8_to_bits as u8ToBits;
  from "EMBED" import u8_from_bits as u8FromBits;
  import "hashes/sha256/sha256" as sha256;
  import "hashes/blake2/blake2s" as macHash;


  ${constants}

  // Verifies a JWT
  // Formats u32[JWT_BLOCKS][16] JWT into a u8[PAYLOAD_LENGTH_PLAINTEXT] array of base64-decoded JWT content
def payloadFromPaddedJWT(u32[JWT_BLOCKS][16] paddedJwt) -> u8[PAYLOAD_LENGTH_PLAINTEXT] {
  // Flatten to bytes to search for aud, sub, and exp substring
  u8[JWT_LENGTH_BASE64] flattened = flatten(paddedJwt);
  u8[PAYLOAD_LENGTH_BASE64] payloadB64 = flattened[HEADER_LENGTH_BASE64+1..JWT_LENGTH_BASE64-PAYLOAD_BASE64_REMAINDER];
  // Convert from base64 to string search for aud, sub, and exp substring
  u8[PAYLOAD_LENGTH_PLAINTEXT] plaintext = fromBase64(payloadB64);
  return plaintext;
}

// Verifies a JWT
def main(private u32[JWT_BLOCKS][16] paddedJwt, u32[8] jwtDigest, u32[8] subCommitment, private u8[SUB_SECRET_LENGTH] subSecret, private u32 subIdx, private u32 audIdx, field expGreaterThan, private u32 expIdx, u8[20] malleabilityAddress) -> bool {
  u8[PAYLOAD_LENGTH_PLAINTEXT] formatted = payloadFromPaddedJWT(paddedJwt);
  // Check that JWT contains valid sub
  u8[SUB_START_LENGTH]  proposedSubStart   = substringAt(formatted, subIdx);
  u8[SUB_MIDDLE_LENGTH] proposedSubMiddle  = substringAt(formatted, subIdx + SUB_START_LENGTH);
  u8[SUB_END_LENGTH]    proposedSubEnd     = substringAt(formatted, subIdx + SUB_START_LENGTH + SUB_MIDDLE_LENGTH);

  assert(proposedSubStart == SUB_START);
  assert(proposedSubEnd == SUB_END);
  assert(macHash(unflatten::<64,1>([...proposedSubMiddle, ...subSecret])) == subCommitment);

  // Check that JWT contains valid aud
  u8[AUD_LENGTH] proposedAud = substringAt(formatted, audIdx);
  assert(proposedAud == AUD);

  // Check that JWT contains valid exp
  u8[EXP_START_LENGTH]  proposedExpStart  = substringAt(formatted, expIdx);
  u8[EXP_MIDDLE_LENGTH] proposedExpMiddle = substringAt(formatted, expIdx + EXP_START_LENGTH);
  u8[EXP_END_LENGTH]    proposedExpEnd    = substringAt(formatted, expIdx + EXP_START_LENGTH + EXP_MIDDLE_LENGTH);
  assert(proposedExpStart == EXP_START);
  assert(proposedExpEnd == EXP_END);
  assert(decimalStringToField(proposedExpMiddle) > expGreaterThan);

  // Check that JWT hashes to jwtDigest
  assert(sha256(paddedJwt) == jwtDigest);

  // Prevent forged proofs by including malleabilityAddress in the proof
  // NOTE: THIS DIDN'T CHANGE NUMBER OF CONSTRAINTS -- ZoKrates seems to automatically add constraints even for unused input, perhaps
  // for our own safety. Still, it may be good to keep this line, even if it is "supserstitious"
  // See https://geometry.xyz/notebook/groth16-malleability 
  for u32 i in 0..20 {
      assert(malleabilityAddress[i] * 0 == 0);
  }
  return true;
}
`

  return [ paramString, source ];
}
function generateAndSaveCircuit(circuitParams) {
  const [ paramString, source ] = generateCircuit(circuitParams);
  const codePath= `generatedCircuits/${paramString}.zok`;
  const compiledPath = `compiled/${paramString}.out`;
  const [pkeyPath, vkeyPath] = [`pvkeys/${paramString}.proving.key`, `pvkeys/${paramString}.verification.key`];
  fs.writeFileSync(codePath, source);
  console.log(`saved as ${paramString}.* in generatedCircuits/ , compiled/, and pvkeys/`);
  console.log("Please run", `\x1b[32m
  zokrates compile -i ${codePath} -o ${compiledPath};
  zokrates setup -i ${compiledPath} -p ${pkeyPath} -v ${vkeyPath};
  \x1b[0m
  `);

  return [ paramString, source ];
}

module.exports = {
  generateCircuit : generateCircuit,
  generateAndSaveCircuit : generateAndSaveCircuit
}
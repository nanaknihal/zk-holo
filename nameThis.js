const { initialize } = require('zokrates-js')
const fs = require("fs");
const path = require("path");
const options = {
    location: "jsVersion.zok", // location of the root module
    resolveCallback: (from, to) => {
        console.log(from + ' is importing ' + to);
        const location = path.resolve(path.dirname(path.resolve(from)), to + '.zok');
        const source = fs.readFileSync(location).toString();
        return { source, location };
    }
};

initialize().then((zokratesProvider) => {
const source = `
from "./base64" import fromBase64;
from "./utils" import decimalStringToField, unflatten, flatten, substringAt, bool_array_to_u8_array, u8_array_to_bool_array;
from "EMBED" import u32_to_bits as u32ToBits;
from "EMBED" import u32_from_bits as u32FromBits;
from "EMBED" import u8_to_bits as u8ToBits;
from "EMBED" import u8_from_bits as u8FromBits;
import "hashes/sha256/sha256" as sha256;
import "hashes/blake2/blake2s" as macHash;


const u32 SUB_START_LENGTH = 9;
// const u32 SUB_START_LENGTH = 8;
const u32 SUB_END_LENGTH = 1;
const u32 SUB_MIDDLE_LENGTH = 11;
const u32 SUB_LENGTH = SUB_START_LENGTH + SUB_END_LENGTH + SUB_MIDDLE_LENGTH;
const u32 SUB_SECRET_LENGTH = 64 - SUB_MIDDLE_LENGTH; // Length of sub claim, including SUB_START and SUB_END. SHOULD NOT BE LESS THAN 16 BYTES FOR SECURE RANDOMNESS
// assert(SUB_SECRET_LENGTH > 15);

const u8[SUB_START_LENGTH] SUB_START = [ 0x22, 0x63, 0x72, 0x65, 0x64, 0x73, 0x22, 0x3a, 0x22 ]; // U8 representation of "creds":" (just used for initial testing purposes, this should be changed to to the next line  later)

// const u8[SUB_START_LENGTH] SUB_START = [ 0x2c, 0x22, 0x73, 0x75, 0x62, 0x22, 0x3a, 0x22 ]; // U8 representation of ,"sub":"
const u8[SUB_END_LENGTH] SUB_END = [ 0x22 ];//, 0x2c, 0x22 ]; // U8 representation of ","

const u32 EXP_START_LENGTH = 8;
const u32 EXP_END_LENGTH = 1;
const u32 EXP_MIDDLE_LENGTH = 10;
const u32 EXP_LENGTH = EXP_START_LENGTH + EXP_END_LENGTH + EXP_MIDDLE_LENGTH; 

const u8[EXP_START_LENGTH] EXP_START = [ 0x22, 0x2c, 0x22, 0x65, 0x78, 0x70, 0x22, 0x3a ];
const u8[EXP_END_LENGTH] EXP_END = [ 0x22 ];//, 0x2c, 0x22 ]; // U8 representation of ","

const u32 AUD_LENGTH = 14;
const u8[AUD_LENGTH] AUD = [34,97,117,100,34,58,34,103,110,111,115,105,115,34]; // U8 representation of   "aud":"gnosis"

const u32 JWT_BLOCKS = 3; // represents length of padded JWT (base64 JWT with periods, header and payload, no signature) in 512-byte multiples 
const u32 JWT_LENGTH_PLAINTEXT = JWT_BLOCKS * 48;
const u32 JWT_NUMBITS_PLAINTEXT = JWT_BLOCKS * 384; // how many bits a JWT is in plaintext

def payloadFriendlyFormat(u32[JWT_BLOCKS][16] paddedJwt) -> u8[JWT_LENGTH_PLAINTEXT] {
    // Flatten to bytes to search for aud, sub, and exp substring
    u8[JWT_BLOCKS*64] flattened = flatten(paddedJwt);
    // Convert from base64 to string search for aud, sub, and exp substring
    u8[JWT_BLOCKS*48] plaintext = fromBase64(flattened);
    // Shift string by two bits to account for . offset between header and payload. This will make the header undecipherable but allow the payload to be deciphered
    bool[JWT_NUMBITS_PLAINTEXT] boolified = u8_array_to_bool_array(plaintext);
    bool[JWT_NUMBITS_PLAINTEXT] shifted = [...boolified[2..JWT_NUMBITS_PLAINTEXT], false, false];
    u8[JWT_BLOCKS*48] result = bool_array_to_u8_array(shifted);
    return result;
  }

// Converts number from a 4-byte string to a u32 integer
def main() -> u8[144] {
  u32[3][16] paddedJwt = [[1702447730,1633112425,1332300406,1498899546,1231958062,1702447722,1668109931,1668892982,1231831673,1647530614,1496463731,1446204013,1231648617,1498961515,1231712105,1513239926],[1664248954,1231648617,1668105845,1514359094,1231834490,1395738931,1464300646,1433101107,1378907202,1500272200,1362250345,1313362228,1634495537,1433102412,1450012782,1664108116],[1699109239,1296382330,1496405353,1279478380,1699234153,1332300152,1315591544,1299863857,1298814330,1231958144,0,0,0,0,0,1336]];
  u8[JWT_LENGTH_PLAINTEXT] formatted = payloadFriendlyFormat(paddedJwt);
  u8[JWT_BLOCKS*64] flattened = flatten(paddedJwt);
  u8[JWT_BLOCKS*48] plaintext = fromBase64(flattened);
  return plaintext;
}`

    // compilation
    const artifacts = zokratesProvider.compile(source, options);

    // computation
    const { witness, output } = zokratesProvider.computeWitness(artifacts, []);
    // const parsedOut = Buffer.concat(JSON.parse(output).map(x=>Buffer.from(x.replace("0x",""), "hex")))
    console.log(
        output,
        Buffer.from(JSON.parse(output).join('').replaceAll('0x',''), 'hex').toString()
    )
    console.log(
        // parsedOut.toString("hex"), parsedOut.toString()
    )
});
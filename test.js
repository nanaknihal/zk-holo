const { initialize } = require('zokrates-js');
const fs = require("fs");
const path = require("path");

const source = `
import "hashes/sha256/sha256"
from "EMBED" import u8_from_bits as u8FromBits
from "EMBED" import u32_to_bits as u32ToBits

// returns a substring of length S, starting at fullString[idx]
def substringAt<F,S>(u8[F] fullString, u32 idx) -> u8[S]:
	u8[S] r = [0; S]
  for u32 i in 0..S do
    r[i] = fullString[idx + i]
	endfor
  return r

// checks whether the substring of length S starting at fullstring[idx] matches "subString"
def hasSubstringAt<F,S>(u8[F] fullString, u8[S] subString, u32 idx) -> bool:
	u8[S] r = substringAt(fullString, idx)
  return (r == subString)


// applies "mask" to "str". returns str & mask bitwise and for every element of the string/mask
def maskString<L>(u8[L] str, u8[L] mask) -> u8[L]:
	u8[L] masked = [0; L]
  for u32 i in 0..L do
    masked[i] = mask[i] & str[i]
  endfor
	return masked //(r == subString)


// Checks masks, but where bytes are the unit of information, and bytes are set to all 1 or all 0
def checkMask<M>(u8[M] mask) -> bool:
  u32 nChanges = 0
  bool valid = ((mask[0] != 255) || (mask[0] != 0)) // Track whether all bytes are 255 or 0
  for u32 i in 1..M do
    nChanges = (mask[i-1] != mask[i]) ? nChanges+1 : nChanges
    valid = valid && ((mask[i] != 255) || (mask[i] != 0))
  endfor
  return valid && ((nChanges == 0) || (nChanges == 1) || (nChanges == 2))


// Checks a substring in flattened starting at audIdx equals a public input, the aud claim
def checkAud<F,A>(u8[F] flattened, u8[A] aud, u32 audIdx) -> bool:
  return hasSubstringAt(flattened, aud, audIdx)


// Checks a JWT's exp claim at expIdx. expIdx should be private but expGreaterThan should be public
// def checkExp<N>(u32[N][16] paddedJwt, u32 expGreaterThan, u32[2] expIdx) -> bool:
//   return paddedJwt[expIdx[0]][expIdx[1]] > expGreaterThan


// @param {extendedSub} the sub claim, plus the following extra characters up to length S for padding as inputs must be of fixed length
// @param {mask} since we don't want to reveal anything after sub, the mask is provided to mask sub with 1s and other bits with 0s
// @param {masked} this can be made public -- this is the sub claim followed by 0s until length S
// @param {subIdx} this is where the the sub starts in flattened
def hasMaskedString<F,S>(u8[F] flattened, u8[S] mask, u8[S] masked, u32 subIdx) -> bool:
  u8[S] extendedSub = substringAt(flattened, subIdx)
  return (maskString(extendedSub, mask) == masked) && (checkMask(mask))

// TODO : PR this to stdlib/utils/casts
def u32sToU8s<N,E>(u32[N] u32s) -> u8[E]:
  u8[E] ret = [0; E]
    for u32 i in 0..N do
      u32 fourI = 4*i
      bool[32] toBits = u32ToBits(u32s[i])
      ret[fourI] = u8FromBits(toBits[0..8])
      ret[fourI+1] = u8FromBits(toBits[8..16])
      ret[fourI+2] = u8FromBits(toBits[16..24])
      ret[fourI+3] = u8FromBits(toBits[24..32])
    endfor
  return ret

// Flatten a N*16 array of u32 to a 1-dimensional array of bytes
def flattenedToBytes<N,F>(u32[N][16] nBy16Arr) -> u8[F]:
  u8[N*128] flattened = [0; N*128]
  u32 iTimes64 = 0
  u32 iTimes64PlusJTimes4 = 0
  for u32 i in 0..N do
    iTimes64 = 64 * i 
    for u32 j in 0..16 do
      iTimes64PlusJTimes4 = iTimes64 + 4 * j
      // iTimes16TimesJTimes8 = iTimes16 * j * 8
      bool[32] newBits = u32ToBits(nBy16Arr[i][j])
      flattened[iTimes64PlusJTimes4] = u8FromBits(newBits[0..8])  
      flattened[iTimes64PlusJTimes4+1] = u8FromBits(newBits[8..16])
      flattened[iTimes64PlusJTimes4+2] = u8FromBits(newBits[16..24])  
      flattened[iTimes64PlusJTimes4+3] = u8FromBits(newBits[24..32])        
    endfor
  endfor
  return flattened

// @param {string} subMasked
// @param {string} serverKey a key deterministically generated by the server (e.g., by signing sub). 
// serverKey is centralized *but* does not mean the server can steal funds -- a valid JWT and serverKey are required for recovery
// having a serverKey prevents being doxxed -- otherwise, hash(sub) must be stored on-chain and can easily be found if somebody knows a sub they want to doxx on-chain
// serverKey can be requested from the server by providing a valid JWT; serverKey can equal hmac(maskedSub, serverSecret), for example. 
// The server can keep the serverSecret secret but give people their unique serverKeys based on their subs for the proof
// The purpose of the serverKey is is pseudorandomness so that nobody except the server can brute-force the encryptedSub which is stored on-chain
// 
// def encryptSub(u8[S] subMasked, serverKey) -> u32[8]:
//   return

// Wrap everything together to check a JWT
def checkJwt<N,A,S>(u32[N][16] paddedJwt, u32[8] jwtHash, private u8[A] audMask, u8[A] audMasked, private u32 audIdx, private u8[S] subMask, u8[S] subMasked, private u32 subIdx, private u8[24] expMask, u8[24] expMasked, private u32 expIdx) -> bool: //allow JWT up to 512 bits
  // Flatten to bytes to search for aud, sub, and exp substring
  u8[N*128] flattened = flattenedToBytes(paddedJwt)  
  // checkAud(flattened, aud, audIdx) 
  return (sha256(paddedJwt) == jwtHash)   &&    hasMaskedString(flattened, audMask, audMasked, audIdx)    &&    hasMaskedString(flattened, subMask, subMasked, subIdx)    &&    hasMaskedString(flattened, expMask, expMasked, expIdx)

def main(private u32[3][16] paddedJwt, u32[8] jwtHash, private u8[24] audMask, u8[24] audMasked, private u32 audIdx, private u8[48] subMask, u8[48] subMasked, private u32 subIdx, private u8[24] expMask, u8[24] expMasked, private u32 expIdx) -> bool:
  return checkJwt(paddedJwt, jwtHash, audMask, audMasked, audIdx, subMask, subMasked, subIdx, expMask, expMasked, expIdx)
`
const options = {
    location: "./root.zok", // location of the root module
    resolveCallback: (from, to) => {
        console.error('a;lkfna;dklvma;sdlkvnmasd;lkcmas;dlkvmasd;lfams;dlf;lfksm')
        const location = path.resolve(path.dirname(path.resolve(from)), to);
        const source = fs.readFileSync(location).toString();
        // return { source, location };
        return {
            source: "def main(): return", 
            location: to
        }
      }
};


const args = [
    [["1702447730","1633112425","1332300406","1498899546","1231958062","1702447722","1668109931","1668892982","1231831673","1647530614","1496463731","1446204013","1231648617","1498961515","1231712105","1513239926"],["1664248954","1231648617","1668105845","1514359094","1231834490","1395738931","1464300646","1433101107","1378907202","1500272200","1362250345","1313362228","1634495537","1433102412","1450012782","1664108116"],["1699109239","1296382330","1496405353","1279478380","1699234153","1332300152","1315591544","1299863857","1298814330","1231958144","0","0","0","0","0","1336"]],
    ["3061472856","343516747","3538476305","3326575927","2228721217","2069433080","3190598334","2108440221"], 
    ["255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","0","0","0","0"],
    ["73","105","119","105","89","88","86","107","73","106","111","105","90","50","53","118","99","50","108","122","0","0","0","0"],
    "48",
    ["255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
    ["101","121","74","106","99","109","86","107","99","121","73","54","73","108","66","121","98","51","82","118","89","50","57","115","86","51","82","109","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
    "20",
    ["255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255","255"],
    ["76","67","74","108","101","72","65","105","79","105","73","120","78","106","85","120","77","122","89","49","77","106","85","122"],
    "140"
]
    
initialize().then((zokratesProvider) => {
    // try {
        // compilation
        const artifacts = zokratesProvider.compile(source, options);

        // computation
        const { witness, output } = zokratesProvider.computeWitness(artifacts, args);

        // run setup
        const keypair = zokratesProvider.setup(artifacts.program);
        console.log("generating proof"); let time_ = Date.now();
        // generate proof
        const proof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
        console.log(Date.now() - time_, "done")
        // // export solidity verifier
        // const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);
        
        // // or verify off-chain
        // const isVerified = zokratesProvider.verify(keypair.vk, proof);

        // console.log(isVerified)
    // } catch(e) {
    //     console.error(e)
    //     return
    // }
});
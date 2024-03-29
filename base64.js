const { initialize } = require('zokrates-js')
initialize().then((zokratesProvider) => {
    const source = `
    /* WARNING: the base64 conversion does not check the input is a valid base64 string
    * If it's invalid, this will give invalid outputs! This is optimized for efficiency, not safety
    * Note that this is not unusual: Javascript's Buffer.from(x, "base64") also gives invalid output rather than errors
    * However, I do not gaurentee this incorrect output is the same as JS' incorrect output
    * This is extremely efficient, taking N constraints where N is input length in bytes. Checking correctness of input would likely reduce
    * this efficiency. It would also eliminate use cases, such as JWTs where there is an invalid base64 character, ".". 
    * For the best of both worlds, it may be useful to make a separate function which checks for valid base64 encoding, so developers can
    * use either or both functions depending on the circumstances 
   */ 
   
   from "EMBED" import u8_from_bits;
   from "EMBED" import u8_to_bits;
   // modified from utils/casts, TODO: PR these to utils/casts
   // convert an array of bool to an array of u8
   // the sizes must match (one u32 for 32 bool) otherwise an error will happen
   def bool_array_to_u8_array<N, P>(bool[N] bits) -> u8[P] {
       assert(N == 8 * P);
   
       u8[P] mut res = [0; P];
   
       for u32 i in 0..P {
           res[i] = u8_from_bits(bits[8 * i..8 * (i + 1)]);
       }
   
       return res;
   }
   def u8_array_to_bool_array<N, P>(u8[N] input) -> bool[P] {
       assert(P == 8 * N);
   
       bool[P] mut res = [false; P];
   
       for u32 i in 0..N {
           bool[8] bits = u8_to_bits(input[i]);
           for u32 j in 0..8 {
               res[i * 8 + j] = bits[j];
           }
       }
   
       return res;
   }
   
   
   
   
   
   //---------------base64-------------//
   
   // char A-Z is 65-90, stored in 8bits char, base64 A-Z is 0-25, stored just in the 6bits necessary. 
   // Therefore, uppercase chars can be converted to base64 by subtracting 65 (and discarding the first two bits of the 8-bit output)
   // The anything above 64 and below 91 can shifted this way by 65 to convert to base64
   const u8 upperCaseEnd = 91;
   const u8 upperCaseOffset = 65;
   
   // Same for lowercase, but with an offset of 71 
   const u8 lowerCaseEnd = 123;
   const u8 lowerCaseOffset = 71;
   
   const u8 numberEnd = 58;
   const u8 numberOffset = 4;
   
   // +, /, and = don't need to be subtracted; they can just be replaced:
   const u8 charPlus = 43;
   const u8 b64Plus = 62;
   const u8 charForwardSlash = 47;
   const u8 b64ForwardSlash = 63;
   const u8 charEquals = 61;
   const u8 b64Equals = 0; //= padding treated as 0
   
   // NOTE: this assumes input is of length divisible by 4 and output is of length input/4*3
   // WARNING: this does not check it's a valid base64 string, and if it's not, this will give invalid outputs! This is optimized for efficiency, not safety
   def fromBase64<I,O>(u8[I] input) -> u8[O] { //can make output shorter
       assert(I % 4 == 0);
       assert((I/4)*3 == O);
       bool[O*8] mut out = [false; O*8];
       for u32 i in 0..I {
           // In ascending order, checks that input is +, then /, then less than the highest uppercase letter, then less than the highest number, then less than the highest lowercase letter. 
           // If any of these checks are true, it does the appropriate replacement, otherwise checks the next condition
           // Currently, ZoKrates only supports one-line if statements such as ternary
           u8 converted = (input[i] == charPlus ? b64Plus : (input[i] == charForwardSlash ? b64ForwardSlash : (input[i] == charEquals ? b64Equals :(input[i] < numberEnd ? input[i] + numberOffset : (input[i] < upperCaseEnd ? input[i] - upperCaseOffset : input[i] - lowerCaseOffset)))));
           bool[8] bin = u8_to_bits(converted);
           out[i*6] = bin[2];
           out[i*6+1] = bin[3];
           out[i*6+2] = bin[4];
           out[i*6+3] = bin[5];
           out[i*6+4] = bin[6];
           out[i*6+5] = bin[7];
       }
       return bool_array_to_u8_array(out);
   }
   
   
   
   // These are test functions and should be in a different file:
   
   
   // def main() -> u8[27] {
   //     bool[216] out = fromBase64::<36,216>([84,87,70,117,101,83,66,111,89,87,53,107,99,121,66,116,89,87,116,108,73,71,120,112,90,50,104,48,73,72,100,118,99,109,115,117]);
   //     u8[27] out2 = bool_array_to_u8_array::<216,27>(out);
   //     // assert(bool_array_to_u8_array::<216,27>(out) == [77,97,110,121,32,104,97,110,100,115,32,109,97,107,101,32,108,105,103,104,116,32,119,111,114,107,46]);
   //     // return true;
   //     return out2;
   // }
   
   def googleJWTConvert() -> u8[660] {
       u8[660] out = fromBase64::<880,660>([101,121,74,104,98,71,99,105,79,105,74,83,85,122,73,49,78,105,73,115,73,109,116,112,90,67,73,54,73,106,103,50,77,84,89,48,79,87,85,48,78,84,65,122,77,84,85,122,79,68,78,109,78,109,73,53,90,68,85,120,77,71,73,51,89,50,81,48,90,84,107,121,77,106,90,106,77,50,78,107,79,68,103,105,76,67,74,48,101,88,65,105,79,105,74,75,86,49,81,105,102,81,46,101,121,74,112,99,51,77,105,79,105,74,104,89,50,78,118,100,87,53,48,99,121,53,110,98,50,57,110,98,71,85,117,89,50,57,116,73,105,119,105,89,88,112,119,73,106,111,105,77,106,85,48,79,84,103,48,78,84,65,119,78,84,89,50,76,84,78,120,97,88,77,49,78,71,49,118,90,109,86,110,78,87,86,107,98,50,100,104,100,87,112,121,99,68,104,121,89,106,100,119,89,110,65,53,99,88,82,117,76,109,70,119,99,72,77,117,90,50,57,118,90,50,120,108,100,88,78,108,99,109,78,118,98,110,82,108,98,110,81,117,89,50,57,116,73,105,119,105,89,88,86,107,73,106,111,105,77,106,85,48,79,84,103,48,78,84,65,119,78,84,89,50,76,84,78,120,97,88,77,49,78,71,49,118,90,109,86,110,78,87,86,107,98,50,100,104,100,87,112,121,99,68,104,121,89,106,100,119,89,110,65,53,99,88,82,117,76,109,70,119,99,72,77,117,90,50,57,118,90,50,120,108,100,88,78,108,99,109,78,118,98,110,82,108,98,110,81,117,89,50,57,116,73,105,119,105,99,51,86,105,73,106,111,105,77,84,65,119,78,122,103,51,79,68,81,48,78,68,99,122,77,84,99,121,77,106,107,52,78,84,81,122,73,105,119,105,90,87,49,104,97,87,119,105,79,105,74,117,89,87,53,104,97,50,53,112,97,71,70,115,81,71,100,116,89,87,108,115,76,109,78,118,98,83,73,115,73,109,86,116,89,87,108,115,88,51,90,108,99,109,108,109,97,87,86,107,73,106,112,48,99,110,86,108,76,67,74,104,100,70,57,111,89,88,78,111,73,106,111,105,100,68,90,113,86,108,57,66,90,48,70,121,84,71,112,117,76,88,70,86,83,108,78,53,98,85,120,111,90,121,73,115,73,109,53,104,98,87,85,105,79,105,74,79,89,87,53,104,97,121,66,79,97,87,104,104,98,67,66,76,97,71,70,115,99,50,69,105,76,67,74,119,97,87,78,48,100,88,74,108,73,106,111,105,97,72,82,48,99,72,77,54,76,121,57,115,97,68,77,117,90,50,57,118,90,50,120,108,100,88,78,108,99,109,78,118,98,110,82,108,98,110,81,117,89,50,57,116,76,50,69,118,81,85,70,85,87,69,70,75,100,122,82,110,77,86,65,51,85,70,90,85,83,50,90,87,85,85,49,108,100,70,100,116,85,86,103,120,81,108,78,118,87,106,108,80,87,84,82,86,85,87,116,76,99,106,100,115,84,68,81,57,99,122,107,50,76,87,77,105,76,67,74,110,97,88,90,108,98,108,57,117,89,87,49,108,73,106,111,105,84,109,70,117,89,87,115,103,84,109,108,111,89,87,119,105,76,67,74,109,89,87,49,112,98,72,108,102,98,109,70,116,90,83,73,54,73,107,116,111,89,87,120,122,89,83,73,115,73,109,120,118,89,50,70,115,90,83,73,54,73,109,86,117,73,105,119,105,97,87,70,48,73,106,111,120,78,106,85,120,77,122,81,53,77,106,99,122,76,67,74,108,101,72,65,105,79,106,69,50,78,84,69,122,78,84,73,52,78,122,77,115,73,109,112,48,97,83,73,54,73,106,65,51,78,84,85,52,79,68,100,108,79,84,73,51,77,122,65,49,90,84,89,48,89,50,69,52,77,87,86,104,77,122,69,51,89,106,89,120,90,71,81,120,89,87,74,106,78,87,70,105,90,106,103,105,102]);
       // u8[660] out2 = bool_array_to_u8_array::<5280,660>(out);
       return out;
   }
   
   def main() -> u8[660] {
       u8[660] stillUgly = googleJWTConvert();
       bool[660*8] boolified = u8_array_to_bool_array(stillUgly);
       bool[660*8] shifted = [...boolified[2..5280], false, false];
       return bool_array_to_u8_array(shifted);
   }
   
   // TODO: test this with = and == padding
    `

    // compilation
    const artifacts = zokratesProvider.compile(source);

    // computation
    const { witness, output } = zokratesProvider.computeWitness(artifacts, []);
    const parsedOut = Buffer.concat(JSON.parse(output).map(x=>Buffer.from(x.replace("0x",""), "hex")))
    console.log(
        parsedOut.toString("hex"), parsedOut.toString()
    )
});


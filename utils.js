const { assert } = require('console')
const ethers = require('ethers')
const { searchForPlainTextInBase64 } = require('wtfprotocol-helpers')
const { and } = require('bitwise-buffer')


// Example JWT
const orcidJwt = 'eyJraWQiOiJwcm9kdWN0aW9uLW9yY2lkLW9yZy03aGRtZHN3YXJvc2czZ2p1am84YWd3dGF6Z2twMW9qcyIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoibG9lOGFqMjFpTXEzMVFnV1NEOXJxZyIsImF1ZCI6IkFQUC1NUExJMEZRUlVWRkVLTVlYIiwic3ViIjoiMDAwMC0wMDAyLTIzMDgtOTUxNyIsImF1dGhfdGltZSI6MTY1MTI3NzIxOCwiaXNzIjoiaHR0cHM6XC9cL29yY2lkLm9yZyIsImV4cCI6MTY1MTM3NTgzMywiZ2l2ZW5fbmFtZSI6Ik5hbmFrIE5paGFsIiwiaWF0IjoxNjUxMjg5NDMzLCJub25jZSI6IndoYXRldmVyIiwiZmFtaWx5X25hbWUiOiJLaGFsc2EiLCJqdGkiOiI1YmEwYTkxNC1kNWYxLTQ2NzUtOGI5MS1lMjkwZjc0OTI3ZDQifQ.Q8B5cmh_VpaZaQ-gHIIAtmh1RlOHmmxbCanVIxbkNU-FJk8SH7JxsWzyhj1q5S2sYWfiee3eT6tZJdnSPInGYdN4gcjCApJAk2eZasm4VHeiPCBHeMyjNQ0w_TZJFhY0BOe7rES23pwdrueEqMp0O5qqFV0F0VTJswyy-XMuaXwoSB9pkHFBDS9OUDAiNnwYakaE_lpVbrUHzclak_P7NRxZgKlCl-eY_q7y0F2uCfT2_WY9_TV2BrN960c9zAMQ7IGPbWNwnvx1jsuLFYnUSgLK1x_TkHOD2fS9dIwCboB-pNn8B7OSI5oW7A-aIXYJ07wjHMiKYyBu_RwSnxniFw'
const googleJwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2MTY0OWU0NTAzMTUzODNmNmI5ZDUxMGI3Y2Q0ZTkyMjZjM2NkODgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiMjU0OTg0NTAwNTY2LTNxaXM1NG1vZmVnNWVkb2dhdWpycDhyYjdwYnA5cXRuLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMjU0OTg0NTAwNTY2LTNxaXM1NG1vZmVnNWVkb2dhdWpycDhyYjdwYnA5cXRuLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAwNzg3ODQ0NDczMTcyMjk4NTQzIiwiZW1haWwiOiJuYW5ha25paGFsQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoidDZqVl9BZ0FyTGpuLXFVSlN5bUxoZyIsIm5hbWUiOiJOYW5hayBOaWhhbCBLaGFsc2EiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUFUWEFKdzRnMVA3UFZUS2ZWUU1ldFdtUVgxQlNvWjlPWTRVUWtLcjdsTDQ9czk2LWMiLCJnaXZlbl9uYW1lIjoiTmFuYWsgTmloYWwiLCJmYW1pbHlfbmFtZSI6IktoYWxzYSIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjUxMzQ5MjczLCJleHAiOjE2NTEzNTI4NzMsImp0aSI6IjA3NTU4ODdlOTI3MzA1ZTY0Y2E4MWVhMzE3YjYxZGQxYWJjNWFiZjgifQ.PXrelpQdJkTxbQw66p6HaSGT5pR6qhkZ8-04hLnVhmrzOJLBkyYisWHzP1t96IWguswMZ4tafg2uCCnra2zkz6BMiBCPrGJdk0l_Kx06FJMX-QNVdt5hW28qM6il94eb0g_OTHCmI28eUJf1rNY8D5NMrG3kXWPDQ8_EkOyySVbu6ED1XFbYgHzo560Ty1-gkQRQKYCuogqrcDBRPF3tqXyg9itCHawm6Kll_GX1TP5zwnwtr5WVrAFYtLJV1_VAEfKWkdU6v6LkAgq4ZjzunFRWBclLVCS2X1JO8iBeGjl_LVVoycvxwojrlZigplQAUSsxmDjlQ4VLH9vINiid6Q'
const twitterJwt = 'eyJraWQiOiJvYWdZIn0.eyJjcmVkcyI6IlByb3RvY29sV3RmIiwiYXVkIjoiZ25vc2lzIiwicmFuZCI6IlMzS1I3WGtfUkc3R0tBYlVHQ2JiNHQ4all1UkhLVmpnc0FTeFYwME9zY1UiLCJleHAiOiIxNjUxMzY1MjUzIn0.WOUI40Dk4bZKszkgfBHsc3Bc0SAQ_cdB6W3F-oGmmY0FhMLfTiVvAFkNIOES_FAUfQlNqq47Gt-THrr6EMcNkOrC6W0nEYjHYn-VByE7xxRdZtSXS_OYDbw8bLQEeaNjcUnJZQ0HYXA0uy4JDNJKbhJCCcrEcK187vbqazpzSZ_tCgbSeqHCmwnakg5obqjrCslehJI8w_aSjEiewUB-fOtTz6S92KvDoozUzli6MjapNDQ8j-kz6wuDpM3EigRdjU8n60xqY0pOeiC8r-AHqPa6bh0ws7f7xrkki2gE0t4eiKEKjWHHKvjf9bgRKtj9G9PRTQVOS1fqF6BBCrqqHQ=='


// const {tbs} = jwtProofParams(orcidJwt)
// console.log(jwtProofParams(twitterJwt, 'ProtocolWtf', '"creds":"'))
// console.log(jwtProofParams(orcidJwt, '0000-0002-2308-9517', '"sub":"'))
// can't search by byte, because payload index is by

const chunk = (arr, chunkSize) => {
    let out = []
    for (let i = 0; i < arr.length; i += chunkSize) {
        const chunk = arr.slice(i, i + chunkSize);
        out.push(chunk)
    }
    return out
}


// Bytes is a Buffer object
// const toU8StringArray = (bytes) => `["${(bytes.map(x=>x)).join('","')}"]`
const toU32Array = (bytes) => {
    let u32s = chunk(bytes.toString('hex'), 8)
    return u32s.map(x=>parseInt(x, 16))
}
const toU8Array = (bytes) => {
    let u8s = chunk(bytes.toString('hex'),2)
    return u8s.map(x=>parseInt(x,16))
}

const toU32StringArray = (bytes) => {
    let u32s = chunk(bytes.toString('hex'), 8)
    return u32s.map(x=>parseInt(x, 16).toString())
}
const toU8StringArray = (bytes) => {
    let u8s = chunk(bytes.toString('hex'),2)
    return u8s.map(x=>parseInt(x,16).toString())
}
// console.log(
//     'snark input', 
//     toU32StringArray(Buffer.from(tbs)), //not base64 (or is base64 hashed?)
//     'numBlocks : ' + toU32StringArray(Buffer.from(tbs)).length % 512
//     )

// console.log(
//     'snark output', 
//     ethers.utils.sha256(Buffer.from(tbs))
//     )


// TEST THIS when message length is 0, 1, 55, 56, 57, 63, 64, 65, 31, 32, 33, 127, 128, 129, 191, 192, 192, 111, 112, 113, and an arbitrary number of bytes

// Note: this assumes input is in bytes, so it assumes number of bits in input is divisible by 8. It won't work for bit arrays
const padBytesForSha256 = (bytes) => {
    let bitsLength = bytes.length * 8
    let remainderBitsLength = bitsLength % 512
                                        // const remainderBytesLength = bytes.length % 64 // 512 bits is 64 bytes
                                        // const remainderBitsLength = bytes.
    let numZeroesToAdd = 447 - remainderBitsLength // padded message will be bits followed by 1 followed by zeroes up to 448, then 64 bits store the length of message
    // NOTE: since 448 and remainderBitsLength are both divisible by 8, numZeroesToAdd = -1 mod 8
    if(numZeroesToAdd < 0) numZeroesToAdd += 512 // number of zeroes added can't be negative! in case there's no room for the 1 + 64 bits of length, add a new block of 0s
    assert((numZeroesToAdd + 1) % 8 == 0, 'should be padding with bytes, not bits') //this line is provably unecessary
    // NOTE: this line assumes there is a first byte to add, which will always be the case if the input length is divisible by 8 bits
    let firstByteToAdd = Buffer.from('80', 'hex') //0b10000000
    let nextBytes = Buffer.from('00'.repeat((numZeroesToAdd / 8)), 'hex')
    let lengthBytes = Buffer.alloc(8)
    lengthBytes.writeBigUint64BE(BigInt(bitsLength))
    return Buffer.concat([
        bytes,
        firstByteToAdd,
        nextBytes,
        lengthBytes
    ])
}

// console.log(padBytesForSha256(Buffer.from('z'.repeat(700))))


// Converts a string the format which will be used as input to the zero knowledge proof circuit
const stringToPaddedU32NBy16StringArray = (str) => 
JSON.stringify(
    chunk(
        toU32StringArray(
            padBytesForSha256(
                Buffer.from(str)
            )
        ),
        16
    )
)

const stringToPaddedU32NBy16Array = (str) => 
    chunk(
        toU32Array(
            padBytesForSha256(
                Buffer.from(str)
            )
        ),
        16
    )

// console.log(
//     'padded',
//     stringToPaddedU32NBy16Array(tbs)
// )
// console.log(
//     'hashed',
//     toU32StringArray(Buffer.from(ethers.utils.sha256(Buffer.from(tbs)).replace('0x',''), 'hex'))
// )


/* @param {string} plaintext 
* @param {string} b64
* @param paddedLength
* @param {integer} idxOffset added to all indices returned 
* @returns {object} 
* - index where shifted plaintext starts in b64. Up to two bytes can be subtracted from index
* because of b64 offsets, so it can look the same in b64 which repeats every three characters.
* - extended base64 from index up to paddedLength
* - mask covering all characters from index to plaintext end with 255 and all characters after plaintext end with 0, for a binary mask
* - masked version of extended base64, i.e. `mask & extendedBase64`
*
* base64 is grouped by three bytes -- 3 original characters for every 4 base64 characters
* thus, 'string' encodes to four base64 characters. But these characters aren't a substring of 'astring'! having a totally changes the encoding
* but do not fear: 'abcstring' does not change the encoding of 'string' as abc has length 3; it's independent
* there's only a 1/3 chance the '","sub":"...","' base64 encoding is actually a substring of the payload's base64 encoding
* that only happens when '","sub":"...","' starts at a payload index which is divisible by three
* so, instead of proving the presence of '","sub":"...","', one can prove the presence of 'x","sub":"...","' or 'xy","sub":"...","' to make it divisible by three
* Shifting left doesn't reveal the length of the sandwich, if the sandwich is '"sub":', rather than '","sub"'
* Shifting left will, at most, reveal '",' and whether the previous part of the payload is a number of chars divisble by 3.
*/
const b64ProofParams = (plaintext, b64, extendedLengthB64, idxOffset=0) => {
    // Find byte at which text occurs in the *plaintext* version
    const [startPt, endPt] = searchForPlainTextInBase64(plaintext, b64)

    // find where the plaintext starts in base64
    const shiftedStartPt = startPt - startPt % 3
    const shiftedStartB64 = shiftedStartPt * 4 / 3

    // and where the plaintext ends in base64
    const lengthPt = endPt - startPt
    const shiftedLengthPt = lengthPt - lengthPt % 3
    const shiftedLengthB64 = shiftedLengthPt * 4 / 3

    // String that will be found in the base64 which includes base64 conversion of: *remainder* characters followed by plaintext
    const shiftedPtToB64 = b64.slice(shiftedStartB64, shiftedStartB64+shiftedLengthB64)
    const extendedPtToB64 = b64.slice(shiftedStartB64, shiftedStartB64+extendedLengthB64)
    // Mask to hide all the unimportant, potentially private characters after the plaintext
    const mask =  'FF'.repeat(shiftedLengthB64) + '00'.repeat(extendedLengthB64 - shiftedLengthB64)
    const masked = and(Buffer.from(extendedPtToB64), Buffer.from(mask, 'hex'))
    
    return {
                // searchString: JSON.stringify(toU8Array(Buffer.from(shiftedPtToB64))),
                // extended : JSON.stringify(toU8Array(Buffer.from(extendedPtToB64))),
                mask: JSON.stringify(toU8Array(Buffer.from(mask, 'hex'))),
                masked: JSON.stringify(toU8Array(masked)),
                idx: idxOffset + shiftedStartB64,
           }

}
const jwtProofParams = (jwt, options) => {
    const {aud, audPaddedLength, sub, subPaddedLength, exp} = options
    const expPaddedLength = 24
    assert((audPaddedLength % 4 == 0) && (subPaddedLength % 4 == 0), 'base64 wraps around every 4 characters (3 ascii characters is 4 base64 characters. padded sandwich length must be a multiple of 4 to avoid invalid strings being searched for')
    const [header, payload, signature] = jwt.split('.')
    const tbs = `${header}.${payload}`
    
    // console.log(sandwich, sandwichPayloadIdx, sandwichPayloadEndIdx)

    
    return {
        // tbs: tbs, 
        preimage: JSON.stringify(stringToPaddedU32NBy16Array(tbs)),
        hash: JSON.stringify(toU32Array(Buffer.from(ethers.utils.sha256(Buffer.from(tbs)).replace('0x',''), 'hex'))),
        aud: b64ProofParams(aud, payload, audPaddedLength, header.length + 1),
        sub: b64ProofParams(sub, payload, subPaddedLength, header.length + 1),
        exp: b64ProofParams(exp, payload, expPaddedLength, header.length + 1),
    }
    // {
    //     tbs: tbs,
    //     sandwich: sandwichB64,
    //     sandwichPadded: sandwichPaddedB64,
    //     sandwichMask: sandwichMaskB64,
    //     sandwichMasked: sandwichMaskedB64,
    //     sandwichStartB64: header.length+1 + shiftedStartInB64,
    //     preimage: JSON.stringify(stringToPaddedU32NBy16Array(tbs)),
    //     hash: JSON.stringify(toU32Array(Buffer.from(ethers.utils.sha256(Buffer.from(tbs)).replace('0x',''), 'hex')))
    // }
}

/*testing*/

let twitterParams = jwtProofParams(twitterJwt, 
    {
        sub:'"creds":"ProtocolWtf","', 
        subPaddedLength: 48,
        aud:'"aud":"gnosis","',
        audPaddedLength: 24,
        exp:'"exp":"1651365253"}'
    })
// console.log(toU32StringArray(Buffer.from(twitterParams.tbs)).length, Buffer.from(twitterParams.tbs).length)
console.log(twitterParams)

function testJWTProofParams(params){
    assert(params.masked.length % 4 == 0)
}
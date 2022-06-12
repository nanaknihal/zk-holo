const { assert } = require('console')
const ethers = require('ethers')

// Example JWT
const jwt = 'eyJraWQiOiJwcm9kdWN0aW9uLW9yY2lkLW9yZy03aGRtZHN3YXJvc2czZ2p1am84YWd3dGF6Z2twMW9qcyIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoibG9lOGFqMjFpTXEzMVFnV1NEOXJxZyIsImF1ZCI6IkFQUC1NUExJMEZRUlVWRkVLTVlYIiwic3ViIjoiMDAwMC0wMDAyLTIzMDgtOTUxNyIsImF1dGhfdGltZSI6MTY1MTI3NzIxOCwiaXNzIjoiaHR0cHM6XC9cL29yY2lkLm9yZyIsImV4cCI6MTY1MTM3NTgzMywiZ2l2ZW5fbmFtZSI6Ik5hbmFrIE5paGFsIiwiaWF0IjoxNjUxMjg5NDMzLCJub25jZSI6IndoYXRldmVyIiwiZmFtaWx5X25hbWUiOiJLaGFsc2EiLCJqdGkiOiI1YmEwYTkxNC1kNWYxLTQ2NzUtOGI5MS1lMjkwZjc0OTI3ZDQifQ.Q8B5cmh_VpaZaQ-gHIIAtmh1RlOHmmxbCanVIxbkNU-FJk8SH7JxsWzyhj1q5S2sYWfiee3eT6tZJdnSPInGYdN4gcjCApJAk2eZasm4VHeiPCBHeMyjNQ0w_TZJFhY0BOe7rES23pwdrueEqMp0O5qqFV0F0VTJswyy-XMuaXwoSB9pkHFBDS9OUDAiNnwYakaE_lpVbrUHzclak_P7NRxZgKlCl-eY_q7y0F2uCfT2_WY9_TV2BrN960c9zAMQ7IGPbWNwnvx1jsuLFYnUSgLK1x_TkHOD2fS9dIwCboB-pNn8B7OSI5oW7A-aIXYJ07wjHMiKYyBu_RwSnxniFw'
const [header, payload, signature] = jwt.split('.')
const tbs = `${header}.${payload}`

const toU32StringArray = (bytes) => `["${(bytes.map(x=>x)).join('","')}"]`
console.log(
    'snark input', 
    toU32StringArray(Buffer.from(tbs)), //not base64 (or is base64 hashed?)
    'numBlocks : ' + toU32StringArray(Buffer.from(tbs)).length % 512
    )

console.log(
    'snark output', 
    ethers.utils.sha256(Buffer.from(tbs))
    )


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
    let nextBytes = Buffer.from('00'.repeat((numZeroesToAdd % 8)-1), 'hex') //-1 because we already added the first byte
    let lengthBytes = Buffer.alloc(8)
    lengthBytes.writeBigUint64BE(BigInt(bitsLength))
    return Buffer.concat([
        bytes,
        nextBytes,
        lengthBytes
    ])
    // Just put the length at the last 64 bytes
    
    // let oneCat = Buffer.concat(
    //     bytes,
    //     firstPadByte
    // )
}

console.log(padBytesForSha256(Buffer.from('abc')))
    
// // console.log()
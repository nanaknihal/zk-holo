const ethers = require('ethers')

// Example JWT
const jwt = 'eyJraWQiOiJwcm9kdWN0aW9uLW9yY2lkLW9yZy03aGRtZHN3YXJvc2czZ2p1am84YWd3dGF6Z2twMW9qcyIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoibG9lOGFqMjFpTXEzMVFnV1NEOXJxZyIsImF1ZCI6IkFQUC1NUExJMEZRUlVWRkVLTVlYIiwic3ViIjoiMDAwMC0wMDAyLTIzMDgtOTUxNyIsImF1dGhfdGltZSI6MTY1MTI3NzIxOCwiaXNzIjoiaHR0cHM6XC9cL29yY2lkLm9yZyIsImV4cCI6MTY1MTM3NTgzMywiZ2l2ZW5fbmFtZSI6Ik5hbmFrIE5paGFsIiwiaWF0IjoxNjUxMjg5NDMzLCJub25jZSI6IndoYXRldmVyIiwiZmFtaWx5X25hbWUiOiJLaGFsc2EiLCJqdGkiOiI1YmEwYTkxNC1kNWYxLTQ2NzUtOGI5MS1lMjkwZjc0OTI3ZDQifQ.Q8B5cmh_VpaZaQ-gHIIAtmh1RlOHmmxbCanVIxbkNU-FJk8SH7JxsWzyhj1q5S2sYWfiee3eT6tZJdnSPInGYdN4gcjCApJAk2eZasm4VHeiPCBHeMyjNQ0w_TZJFhY0BOe7rES23pwdrueEqMp0O5qqFV0F0VTJswyy-XMuaXwoSB9pkHFBDS9OUDAiNnwYakaE_lpVbrUHzclak_P7NRxZgKlCl-eY_q7y0F2uCfT2_WY9_TV2BrN960c9zAMQ7IGPbWNwnvx1jsuLFYnUSgLK1x_TkHOD2fS9dIwCboB-pNn8B7OSI5oW7A-aIXYJ07wjHMiKYyBu_RwSnxniFw'
const [header, payload, signature] = jwt.split('.')
const tbs = `${header}.${payload}`

const toU32StringArray = (bytes) => `["${(bytes.map(x=>x)).join('","')}"]`
console.log(
    'snark input', 
    toU32StringArray(Buffer.from(tbs)) //not base64 (or is base64 hashed?)
    )

console.log(
    'snark output', 
    ethers.utils.sha256(Buffer.from(tbs))
    )
    
// console.log()
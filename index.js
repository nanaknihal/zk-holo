exports.handler = async function(event_, context, callback) {
    const ans = await proveJWT("google", event_.body.jwt, "0xC8834C1FcF0Df6623Fc8C8eD25064A4148D99388");
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": ans
    }
}

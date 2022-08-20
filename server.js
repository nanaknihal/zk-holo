const { proveJWT } = require("./proofgen.js");
const express = require("express");
const app = express();
const port = 3000;

app.post("/proofgen/:jwtType/", (req, res) => {
    return proveJWT(req.body.jwtType, req.body.jwt, req.body.address);
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`)
});
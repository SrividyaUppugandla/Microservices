//dependencies : For encrypting the payload information
var encryption = require('./encryption');

//dependencies : JWT module with password and encryption type
var jwt = require('jsonwebtoken');
var jwtSecret = process.env.secretKey;
var encryptionType = "HS256";

//generate JWT token with the given payload. Encrypt the payload and form JWT token with signature
exports.generateJWT= function(payload,callback) {

    if(payload) {
        encryption.encryptData(JSON.stringify(payload), function (err, encryptedData) {
            if(err) {
                return callback(err);
            }
            else {
                var jsonInfo = { payload : encryptedData};
                jwt.sign(jsonInfo, jwtSecret, { algorithm: encryptionType }, function (err, token) {
                    if(err){
                        return callback(err);
                    }
                    else{
                        return callback(null,token);
                    }
                });
            }
        });
    }
    else {
        return callback({"error":"payload is not available"});
    }
};

//Validate and retrieve the payload information by decrypting. callback with actual payload JSON
exports.validateJWT= function(token,callback) {

    if(token) {
        jwt.verify(token, jwtSecret, function(err, decoded) {
            if (err) {

                return callback(err);
            }
            else{
                encryption.decryptData(decoded.payload, function (err, decryptedData) {
                    if(err) {
                        return callback(err);
                    }
                    else {
                        var decrypted = JSON.parse(decryptedData);
                        return callback(null,decrypted);
                    }
                });
            }
        });
    }
    else {
        return callback({"error":"token is not available"});
    }
};

//Verify the JWT token signature. Also the expiry of JWT token sent in headers
exports.verifyJWT= function(req,res,next) {

    jwt.verify(req.headers.token, jwtSecret, function(err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            encryption.decryptData(decoded.payload, function (err, decryptedData) {
                if(err) {
                    res.send({error:"Not Authorised"}, 401);
                }
                else {

                    if((decryptedData.iat + decryptedData.expiresIn) > (Date.now() / 1000)){
                        res.send({error:"Token has expired !!"}, 401);
                    }
                    else{
                        next();
                    }
                }
            });
        }
    });
};


var jwt = require('jsonwebtoken');
var encryption = require('./encryption');

var jwtSecret = process.env.secretKey;
var encryptionType = "HS256";


exports.generateJWT= function(payload,callback) {



    //var encryptionType = process.env.algorithmName;

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


};

exports.validateJWT= function(token,callback) {


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
};

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


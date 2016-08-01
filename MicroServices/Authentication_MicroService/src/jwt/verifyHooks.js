var jwt = require('jsonwebtoken');
var validateJwt = require('./jwt');

var jwtSecret = process.env.secretKey;
var encryptionType = "HS256";



exports.verifyPrehooksClearanceForFacebook= function(req,res,next) {


    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "facebook" && (decoded.iat + decoded.expiresIn) > (Date.now() / 1000)) {
                    next();
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};

exports.verifyPrehooksClearanceForGoogle= function(req,res,next) {


    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "google" && ((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))) {
                next();
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};

exports.verifyPrehooksClearanceForLinkedin= function(req,res,next) {


    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "linkedin" && ((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))) {
                next();
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};

exports.verifyPrehooksClearanceForTwitter= function(req,res,next) {


    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "twitter" && ((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))) {
                next();
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};


exports.verifyAuthComplete= function(token,next) {


    validateJwt.validateJWT(token, function (err, decoded) {
        if (err) {

            next({error:"Not Authorised"});
        }
        else{
            if(decoded && decoded.nextCall === "/auth/complete" && decoded.authenticationType && decoded.userProfile && ((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))) {
                next(null,decoded);
            }
            else {
                next({error:"Not a valid token"});
            }
        }
    });
};

exports.verifyApiKey= function(req,res,next) {


    if(req.headers.apikey && req.headers.apikey===process.env.apiKey) {
        next();
    }
    else {
        res.send({error:"Not Authorised. Invalid apiKey"}, 401);
    }
};

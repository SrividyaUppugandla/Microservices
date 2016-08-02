//dependencies
var validateJwt = require('./jwt');


//Verify signature and as well as all hooks are cleared for facebook.
// check if authenticationType is facebook. Check for token expiry as well
exports.verifyPrehooksClearanceForFacebook= function(req,res,next) {

    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "facebook") {

                if(((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))){
                    res.send({error:"Token has expired !!"}, 401);
                }
                else{
                    next();
                }
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};

//Verify signature and as well as all hooks are cleared for google.
// check if authenticationType is google. Check for token expiry as well
exports.verifyPrehooksClearanceForGoogle= function(req,res,next) {

    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "google" ) {

                    if(((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))){
                        res.send({error:"Token has expired !!"}, 401);
                    }
                    else{
                        next();
                    }
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};

//Verify signature and as well as all hooks are cleared for Linkedin.
// check if authenticationType is linkedin. Check for token expiry as well
exports.verifyPrehooksClearanceForLinkedin= function(req,res,next) {

    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "linkedin" ) {

                if(((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))){
                    res.send({error:"Token has expired !!"}, 401);
                }
                else{
                    next();
                }
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};

//Verify signature and as well as all hooks are cleared for twitter.
// check if authenticationType is twitter. Check for token expiry as well
exports.verifyPrehooksClearanceForTwitter= function(req,res,next) {

    validateJwt.validateJWT(req.params.token, function (err, decoded) {
        if (err) {

            res.send({error:"Not Authorised"}, 401);
        }
        else{
            if(decoded && decoded.isPrehookClear === true && decoded.authenticationType === "twitter") {

                if(((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))){
                    res.send({error:"Token has expired !!"}, 401);
                }
                else{
                    next();
                }
            }
            else {
                res.send({error:"Not Authorised"}, 401);
            }
        }
    });
};


//Verify signature and as well as all validation for calling /auth/complete.
// check if authenticationType and userprofile are available. Check for token expiry as well
exports.verifyAuthComplete= function(token,next) {

    validateJwt.validateJWT(token, function (err, decoded) {
        if (err) {

            next({error:"Not Authorised"});
        }
        else{
            if(decoded && decoded.nextCall === "/auth/complete" && decoded.authenticationType && decoded.userProfile ) {

                if(((decoded.iat + decoded.expiresIn) > (Date.now() / 1000))){
                    next({error:"Token is expired"});
                }
                else{
                    next(null,decoded);
                }
            }
            else {
                next({error:"Not a valid token"});
            }
        }
    });
};


//Verify API key on headers with the env apiKey
exports.verifyApiKey= function(req,res,next) {

    if(req.headers.apikey && req.headers.apikey===process.env.apiKey) {
        next();
    }
    else {
        res.send({error:"Not Authorised. Invalid apiKey"}, 401);
    }
};

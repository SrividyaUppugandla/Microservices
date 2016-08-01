//dependencies : Crypto module with password and encryption type
var crypto = require('crypto');
var cipherPwd = 'fare54ndlloye27k';
var encryptionType = 'aes192';
var config = require('./../OAuth.json');

//encrypt data using crypto
exports.encryptData = function (data, callback) {
    if (data) {
        var cipher = crypto.createCipher(encryptionType, cipherPwd);
        try {
            var encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            callback(null,encrypted);
        } catch (exception) {
            callback(exception);
        }
    }
    else {
        callback(false);
    }
};

//decrypt data using crypto
exports.decryptData = function (data, callback) {
    if (data) {
        var decipher = crypto.createDecipher(encryptionType, cipherPwd);
        try {
            var decrypted = decipher.update(data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            callback(null,decrypted);
        } catch (exception) {
            callback(exception);
        }
    }
    else {
        callback(false);
    }
};

//verify if callbackUrl is present in query params
exports.verifyOauthRequest = function (req, res, next) {
    if(req.query.callbackUrl) {
        next();
    }
    else {
        res.send({error:"Bad Request. No redirectUrl found in query parameters"}, 400);
    }
};

//verify if callbackUrl is present in query params and also store callbackUrl in session
exports.verifyTwitterOauthRequest = function (req, res, next) {
    if(req.query.callbackUrl) {
        res.cookie('callbackUrl', req.query.callbackUrl, {httpOnly: true});
        next();
    }
    else {
        res.send({error:"Bad Request. No redirectUrl found in query parameters"}, 400);
    }
};


//verify if all required credentials available in VCAP for Facebook
exports.verifyFacebook = function (req, res, next) {
    if (process.env.configuration && process.env.configuration.facebook && process.env.configuration.facebook.clientID && process.env.configuration.facebook.clientSecret && process.env.configuration.facebook.scope) {
        next();
    }
    else {
        res.send({error:"Not found"}, 404);
    }
};

//verify if all required credentials available in VCAP for Google
exports.verifyGoogle = function (req, res, next) {
    if (process.env.configuration && process.env.configuration.google && process.env.configuration.google.clientID && process.env.configuration.google.clientSecret && process.env.configuration.google.scope) {
        next();
    }
    else {
        res.send({error:"Not found"}, 404);
    }
};

//verify if all required credentials available in VCAP for Linkedin
exports.verifyLinkedin = function (req, res, next) {
    if (process.env.configuration && process.env.configuration.linkedin && process.env.configuration.linkedin.clientID && process.env.configuration.linkedin.clientSecret && process.env.configuration.linkedin.scope) {
        next();
    }
    else {
        res.send({error:"Not found"}, 404);
    }
};

//verify if all required credentials available in VCAP for Twitter
exports.verifyTwitter = function (req, res, next) {
    if (process.env.configuration && process.env.configuration.twitter && process.env.configuration.twitter.clientID && process.env.configuration.twitter.clientSecret) {
        next();
    }
    else {
        res.send({error:"Not found"}, 404);
    }
};



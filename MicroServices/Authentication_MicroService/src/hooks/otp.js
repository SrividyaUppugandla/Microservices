/**
 * Created by 423919 on 5/18/2016.
 * This is the Otp module which generate a token and validate the same
 */
// dependencies for this module
//var crypto = require('crypto');
//var cipherPwd = 'oyeilyodd';
//var encryptionType = 'aes192';
var randomString = require("randomstring");
var bodyParser = require('body-parser');
var jsonParser = bodyParser.json();
var Jwt = require("./../jwt/jwt.js");
var async = require('async');
//constructor
var Otp = function () {

};


// This api is use to generate an OTP based on the length,type and expiry
// time

Otp.prototype.generateOtp = function (app) {
    // route for generate Otp
    app.post("/generateOtp", [jsonParser,Jwt.verifyJWT],function (req, res) {

        if(req.headers.token){
            var jwtToken = req.headers.token;

            // validating the Jwt and get the decodedInfo
            var validateJwt = function(callback){
                Jwt.validateJWT(jwtToken,callback);
            };

            //This will generate Otp according to user defined configurations
            var generateOtp = function(tokenDetails,callback){
                console.log("tokenDetails   "+JSON.stringify(tokenDetails))
                if(tokenDetails.currentHook && tokenDetails.hooks && tokenDetails.totalNoOfhooks ) {
                    var otpConfig = process.env.channels.OTP;
                    //var otpConfig = {
                    //    "length": "5",
                    //    "type": "alphanumeric",
                    //    "expiryTime": 15
                    //}
                    var otpOptions = {};
                    //creating the otpOptions from the req.body.json
                    otpOptions.length = (otpConfig && otpConfig.length) ? otpConfig.length : 4;
                    otpOptions.charset = (otpConfig && otpConfig.type) ? otpConfig.type : 'numeric';
                    var expiryTime = (otpConfig && otpConfig.expiryTime) ? otpConfig.expiryTime : 15;
                    var otpCode = randomString.generate(otpOptions);
                    var otpGenTime = Date.now();
                    var otpExpiryTime = otpGenTime + (expiryTime * 60000);
                    tokenDetails.otpExpiryTime = otpExpiryTime;
                    tokenDetails.otpCode = otpCode;
                    return callback(null, tokenDetails);
                }
                else{

                    return callback({"error":"Not Authorised"});
                }

            };

            var sendOtp = function(tokenDetails,callback){

                if(tokenDetails.hooks[tokenDetails.currentHook - 1].channelprovider === 'twilio') {
                    var twilioConfig = process.env.channelproviders.twilio;
                    //var twilioConfig = {
                    //    "accountid": "AC728b20a72ea48a175a0cf47d11a6aa56",
                    //    "accounttoken": "1c84da28903505f762c727fe1bd65700"
                    //};
                    if (req.body.toRecipient && req.body.fromNo) {
                        //hooking the twilio to OTP
                        var twilio = require("./twilioservice.js");
                        var twilioObj = new twilio();
                        //creating the options for twilio
                        var msgObj = {
                            "accountSID": twilioConfig.accountid,
                            "authToken": twilioConfig.accounttoken,
                            "to": req.body.toRecipient,
                            "from": req.body.fromNo,
                            "body": "OTP pin is " + tokenDetails.otpCode

                        };

                        twilioObj.sendMessage(msgObj, function (err, result) {
                            res.header("Access-Control-Allow-Origin", "*");
                            res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                            if (err) {

                                return callback(err);
                            }
                            else {
                                return callback(null,tokenDetails);

                            }

                        });
                    }
                    else {

                        return callback({"error":"From Number / To Number is missing"});
                    }



                }else if (tokenDetails.hooks[tokenDetails.currentHook - 1].channelprovider === 'sendgrid') {

                    var sendmail = require("./sendgridservice.js");
                    var sendmailObj = new sendmail();

                    var sendGridConfig = process.env.channelproviders.sendgrid;
                    //var sendGridConfig = {
                    //    "accountid": "r8skU2912a",
                    //    "accounttoken": "BPRV4rL9N7jM9272"
                    //};

                    if (req.body.toRecipient && req.body.fromMail) {
                        //creating the options for sendgrid
                        var msgObj = {
                            "accountSID": sendGridConfig.accountid,
                            "authToken": sendGridConfig.accounttoken,
                            "toRecipient": req.body.toRecipient,
                            "fromMail": req.body.fromMail,
                            "subject": "Please find the otp",
                            "text": "OTP pin is " + tokenDetails.otpCode
                        };
                        sendmailObj.sendMail(msgObj, function (err, result) {
                            res.header("Access-Control-Allow-Origin", "*");
                            res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                            if (err) {

                                return callback(err);
                            }
                            else {
                                return callback(null,tokenDetails);

                            }
                        });
                    }
                    else{
                        return callback({"error":"fromMail / To Mail is missing"});
                    }
                }
                else{
                    return callback({"error":tokenDetails.hooks[tokenDetails.currentHook - 1].channelprovider +" not supported now"});
                }
            };

            // creates a JWT token
            var createJwt = function(tokenDetails,callback){

                delete tokenDetails.iat;
                tokenDetails.iat = Math.floor(Date.now() / 1000) - 30 //TODO :: Check this if this is reqd for expiry -- backdate a jwt 30 seconds
                delete tokenDetails.nextCall;
                tokenDetails.nextCall = '/validateOtp'
                Jwt.generateJWT(tokenDetails,callback);
            };

            var finalCallback = function(err,result){

                if(err){
                    res.send(JSON.stringify(err), 400);
                }
                else{
                    //setting the next api call
                    var resp = {};
                    resp.nextCall = '/validateOtp';
                    resp.token = result;
                    res.setHeader("Content-Type","application/json");
                    res.send(resp, 303);
                }
            };

            async.waterfall([validateJwt,generateOtp,sendOtp,createJwt],finalCallback);


        }else{
            res.setHeader("Content-Type","application/json");
            res.send({"error":"Not authorised"}, 401);
        }


    });

};

// This api is used to validate the otp given by the user,
// with the key
Otp.prototype.validateOtp = function (app) {

    app.post("/validateOTP", [jsonParser,Jwt.verifyJWT], function (req, res) {


        if(req.headers.token){

            var jwtToken = req.headers.token;
            var statusCode;
            var channelprovider,message;

            if(req.body.otpCode) {

                // validating the Jwt and get the decodedInfo
                var validateJwt = function (callback) {
                    Jwt.validateJWT(jwtToken, callback);
                };

                // validates the OTP code
                var validateOtp = function (tokenDetails, callback) {
                    if(tokenDetails.currentHook && tokenDetails.hooks && tokenDetails.totalNoOfhooks ) {
                        var currentTime = Date.now();
                        var status = {};
                        if (req.body.otpCode === tokenDetails.otpCode && tokenDetails.otpExpiryTime > currentTime) {
                            status.status = "OTP is validated successfully";

                            return callback(null, tokenDetails);
                        } else {
                            status.status = "OTP validation failed ";
                            return callback(status);
                        }
                    }
                    else{

                        return callback({"error":"Not Authorised"});
                    }

                };

                // creates a JWT token
                var createJwt = function(tokenDetails,callback){
                    var nextCall,userProfile;

                    delete tokenDetails.otpExpiryTime;
                    delete tokenDetails.otpCode;

                    //creates payload for Jwt
                    if(tokenDetails.currentHook < tokenDetails.totalNoOfhooks){

                        tokenDetails.currentHook = (tokenDetails.currentHook + 1);

                        if(tokenDetails.hooks[tokenDetails.currentHook - 1 ].channel === 'OTP'){
                            nextCall = '/generateOtp';
                            channelprovider = tokenDetails.hooks[tokenDetails.currentHook - 1 ].channelprovider;
                            statusCode = 303
                        }
                        if(tokenDetails.hooks[tokenDetails.currentHook - 1].channel === 'Captcha'){
                            nextCall = '/generateCaptcha';
                            statusCode = 303;
                        }

                    }else if(tokenDetails.hookType == 'prehook'){
                        delete tokenDetails.hooks;
                        delete tokenDetails.totalNoOfhooks;
                        delete tokenDetails.currentHook;
                        delete tokenDetails.hookType;
                        tokenDetails.isPrehookClear = true;
                        nextCall = '/'+tokenDetails.authenticationType;
                        statusCode = 302;
                        message =  "pass callbackUrl as query param"
                    }
                    else if(tokenDetails.hookType == 'posthook'){
                        delete tokenDetails.hooks;
                        delete tokenDetails.totalNoOfhooks;
                        delete tokenDetails.currentHook;
                        delete tokenDetails.hookType;
                        userProfile = tokenDetails.userProfile;
                        statusCode = 200;

                    }
                    delete tokenDetails.nextCall;

                    tokenDetails.nextCall = nextCall;

                    delete tokenDetails.iat;
                    tokenDetails.iat = Math.floor(Date.now() / 1000) - 30 //TODO :: Check this if this is reqd for expiry -- backdate a jwt 30 seconds

                    var onCallback = function(err,token){
                        if(err){
                            return callback(err);
                        }
                        else{
                            var resp = {};

                            if(nextCall === ("/"+tokenDetails.authenticationType)) {
                                resp.nextCall = nextCall + "/" + token;
                            }
                            else{
                                resp.nextCall = nextCall;
                                resp.token = token;
                            }
                           if(nextCall === '/generateOtp'){
                               resp.channelprovider = channelprovider;
                           }


                            var responseJson = {
                                nextCall    :   nextCall+"/"+token, //TODO :: Check if token needs to be appended or send separately
                                message     :   "pass callbackUrl as query param"
                            }

                            if(userProfile && Object.keys(userProfile).length) {
                                return callback(null, userProfile);
                            }
                            else{
                                return callback(null, resp);
                            }
                        }
                    }

                    Jwt.generateJWT(tokenDetails,onCallback);
                };


                var finalCallback = function (err, result) {

                    if (err) {
                        res.send(JSON.stringify(err), 400);
                    }
                    else {

                        res.setHeader("Content-Type", "application/json");
                        res.send(result, statusCode);
                    }
                };
                async.waterfall([validateJwt,validateOtp,createJwt], finalCallback)

            }
            else{
                res.setHeader("Content-Type","application/json");
                res.send({"error":"Otp code not provided"}, 400);
            }
        }
        else{
            res.setHeader("Content-Type","application/json");
            res.send({"error":"Not authorised"}, 401);
        }



    });
};

module.exports = Otp;

// dependencies
var config = require('./OAuth.json');
var jwtVerifyAuthComplete = require('./../jwt/verifyHooks');
var jwt = require('./../jwt/jwt');


function authComplete(app){

    //TODO :: Add API key check middleware

    app.post('/auth/complete',[jwtVerifyAuthComplete.verifyApiKey,jwt.verifyJWT], function(req, res) {

            //check if the nextCall is "/auth/complete"  expiry   and   authenticationType
            jwtVerifyAuthComplete.verifyAuthComplete(req.headers.token, function(err,payload) {

                if(err) {
                    res.send({error:"Not Authorised"}, 401);
                }
                else if ( config.posthooks && config.posthooks[payload.authenticationType]) {

                    var postHooks = config.posthooks[payload.authenticationType];
                    var totalNoOfPosthooks = postHooks.length;
                    var hookType = "posthook";
                    var authenticationType = payload.authenticationType;

                    var nextCall;
                    var channel = postHooks[0].channelprovider;

                    if (postHooks[0].channel === 'OTP') {
                        nextCall = '/generateOtp'
                    }
                    if (postHooks[0].channel === 'Captcha') {
                        nextCall = '/generateCaptcha'
                    }
                    //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(facebook), preparedBy(/auth/facebook)
                    var jwtInfo = {
                        userProfile     : payload.userProfile,
                        totalNoOfhooks  : totalNoOfPosthooks,
                        hooks           : postHooks,
                        currentHook     : 1,  //TODO :: check if we can have any ID
                        hookType        : hookType,
                        authenticationType: authenticationType,
                        nextCall        : nextCall,
                        channelprovider : channel,
                        iat             : Math.floor(Date.now() / 1000) - 30, //TODO :: Check this if this is reqd for expiry -- backdate a jwt 30 seconds
                        expiresIn       : 900
                        //preparedBy          :   authenticationType
                    }

                    // sign JWT token
                    jwt.generateJWT(jwtInfo, function (err, token) {
                        //Prepare jwt payload info json with all required values like nextcall, channel, jwt-token
                        var responseJson = {
                            nextCall            : nextCall, //TODO :: Parse the json and check for type of method call
                            channelprovider     : channel, //TODO :: parse the JSON and get channel type then assign
                            token               : token
                        }
                        res.send(responseJson, 303);
                    });
                }
                else {
                    res.send(payload.userProfile, 200);
                }
            });
    });

}

module.exports = authComplete;

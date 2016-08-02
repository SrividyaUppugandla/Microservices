var jwtVerifyPrehooks = require('./../../jwt/verifyHooks');
var jwt = require('./../../jwt/jwt');

//Read the config key value from env variables. This will return a JSON string with '=>' symbol in place of ':'
//Replace '=>' symbol with ':' to convert to JSON string and parse to retrieve JSON object
var envJson;
var config;
if(process.env.config) {
    envJson = process.env.config;
    envJson = envJson.replace(/=>/g, ':');
    config = JSON.parse(envJson);
}

//  This function is common for all providers. Called during initial call(eg : /auth/facebook)
//  This function checks for prehooks of the given provider and prepares JWT info with the required info. Status code is 303 if any prehooks available
//
//  If no prehooks are available then JWT token is prepared without prehooks info and clearance info for next redirection call. Status code is 302

exports.authProvider= function(provider,callback) {

    if ( config.prehooks && config.prehooks[provider]) {
        var callbackJson
        var preHooks = config.prehooks[provider];
        var totalNoOfPrehooks = preHooks.length;
        var hookType = "prehook";
        var authenticationType = provider;

        var nextCall;
        var channel = preHooks[0].channelprovider;

        //Check for the channel and assign nextCall
        if(preHooks[0].channel === 'OTP'){
            nextCall = '/generateOtp'
        }
        if(preHooks[0].channel === 'Captcha'){
            nextCall = '/generateCaptcha'
        }

        //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(facebook), preparedBy(/auth/facebook)
        var jwtInfo = {
            totalNoOfhooks      :   totalNoOfPrehooks,
            hooks               :   preHooks,
            currentHook         :   1,
            hookType            :   hookType,
            authenticationType  :   authenticationType,
            nextCall            :   nextCall,
            channelprovider     :   channel,
            iat                 :   Math.floor(Date.now() / 1000) - 30, //backdate a jwt 30 seconds to compensate the next execution statements
            expiresIn           :   900
            //preparedBy          :   authenticationType
        }

        // sign JWT token
        jwt.generateJWT(jwtInfo, function(err, token) {
            if(err) {
                callbackJson = {
                    responseJson    :   err,
                    statusCode      :   500
                }
                callback(callbackJson);
            }
            else {
                //Prepare jwt payload info json with all required values like nextcall, channel, jwt-token
                var responseJson = {
                    nextCall            :   nextCall,
                    channelprovider     :   channel,
                    token               :   token
                }

                callbackJson = {
                    responseJson    :   responseJson,
                    statusCode      :   303
                }
                callback(callbackJson);
            }
        });
    }
    else {
        var callbackJson;
        var authenticationType = provider;
        var nextCall = "/"+provider;
        //send the next method to be called is the redirection to /facebook API with JWT token PreHooks Cleared message
        //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(facebook), preparedBy(/auth/facebook)
        var jwtInfo = {
            authenticationType  :   authenticationType,
            isPrehookClear      :   true,
            nextCall            :   nextCall,
            iat                 :   Math.floor(Date.now() / 1000) - 30, //backdate a jwt 30 seconds to compensate the next execution statements
            expiresIn           :   900
            //preparedBy          :   authenticationType
        }

        // sign JWT token
        jwt.generateJWT(jwtInfo, function(err, token) {
            if(err) {
                callbackJson = {
                    responseJson    :   err,
                    statusCode      :   500
                }
                callback(callbackJson);
            }
            else {
                //Prepare response json
                var responseJson = {
                    nextCall    :   nextCall+"/"+token,
                    message     :   "pass callbackUrl as query param"
                }

                callbackJson = {
                    responseJson    :   responseJson,
                    statusCode      :   302
                }
                callback(callbackJson);
            }
        });
    }
};


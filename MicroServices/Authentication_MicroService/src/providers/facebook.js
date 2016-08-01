// dependencies
var FacebookStrategy = require('passport-facebook').Strategy;
var passport = require('passport');
var security = require('./middleware/security');
var scope = [];
// var config = require('./OAuth.json');
var jwtVerifyPrehooks = require('./../jwt/verifyHooks');
var jwt = require('./../jwt/jwt');


var envJson;
var config;

if(config.process.env) {
    envJson = config.process.env;
    envJson = envJson.replace(/=>/g, ':');
    config = JSON.parse(envJson);
}



// Configure the Facebook strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Facebook API on the user's
// behalf, along with the user's profile.  The function must invoke `done`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.
if (config.configuration && config.configuration.facebook && config.configuration.facebook.clientID && config.configuration.facebook.clientSecret && config.configuration.facebook.scope) {
    scope = config.configuration.facebook.scope;
    passport.use(new FacebookStrategy({
            clientID: config.configuration.facebook.clientID,
            clientSecret: config.configuration.facebook.clientSecret
        },
        function(accessToken, refreshToken, profile, done) {
            // The function must invoke `done` with a user object, which will be set at `req.user`
            // in route handlers after authentication.(/auth/facebook/callback will receive `req.user`)
            var user = {
                "accessToken" : accessToken,
                "refreshToken" : refreshToken,
                "profile" : profile
            };
            done(null, user);
        }
    ));
}


function facebook(app){

    // GET /facebook
    //   Use passport.authenticate() as route middleware to authenticate the
    //   request.  The first step in Facebook authentication will involve
    //   redirecting the user to facebook.com.  After authorization, Facebook will
    //   redirect the user back to this application at /auth/facebook/callback
    app.get('/facebook/:token', [
        //TODO :: Add security check for JWT and also check if all prehooks are cleared
        security.verifyFacebook,    //verify if all required credentials available in VCAP
        security.verifyOauthRequest, //verify if callbackUrl is present in query params
        jwtVerifyPrehooks.verifyPrehooksClearanceForFacebook //Verify the clearance for facebook(all prehooks and authentication type)
    ], function(req,res,next) {
        passport.authenticate(
            'facebook',{ authType: 'rerequest', scope: scope ,callbackURL: '/auth/facebook/callback' , state: req.query.callbackUrl}
        ) (req,res,next);
    });



    //TODO :: add middleware check for apiKey
    app.post('/auth/facebook', [jwtVerifyPrehooks.verifyApiKey], function (req, res) {
            //TODO :: Change parsing of VCAP env variable
            //TODO :: prehook of facebook will be an array parsing
            if ( config.prehooks && config.prehooks.facebook) {
                var preHooks = config.prehooks.facebook;
                var totalNoOfPrehooks = preHooks.length;
                var hookType = "prehook";
                var authenticationType = "facebook";

                var nextCall;
                var channel = preHooks[0].channelprovider;

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
                    currentHook         :   1,  //TODO :: check if we can have any ID
                    hookType            :   hookType,
                    authenticationType  :   authenticationType,
                    nextCall            :   nextCall,
                    channelprovider     :   channel,
                    iat                 :   Math.floor(Date.now() / 1000) - 30, //TODO :: Check this if this is reqd for expiry -- backdate a jwt 30 seconds
                    expiresIn           :   900
                    //preparedBy          :   authenticationType
                }

                // sign JWT token
                jwt.generateJWT(jwtInfo, function(err, token) {
                    if(err) {
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(err, 500);
                    }
                    else {
                        //Prepare jwt payload info json with all required values like nextcall, channel, jwt-token
                        var responseJson = {
                            nextCall            :   nextCall, //TODO :: Parse the json and check for type of method call
                            channelprovider     :   channel, //TODO :: parse the JSON and get channel type then assign
                            token               :   token
                        }
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(responseJson, 303);
                    }
                });
            }
            else {
                var authenticationType = "facebook";
                var nextCall = "/facebook";
                //send the next method to be called is the redirection to /facebook API with JWT token PreHooks Cleared message
                //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(facebook), preparedBy(/auth/facebook)
                var jwtInfo = {
                    authenticationType  :   authenticationType,
                    isPrehookClear      :   true,
                    nextCall            :   nextCall,
                    iat                 :   Math.floor(Date.now() / 1000) - 30, //TODO :: Check this if this is reqd for expiry -- backdate a jwt 30 seconds
                    expiresIn           :   900
                    //preparedBy          :   authenticationType
                }

                // sign JWT token
                jwt.generateJWT(jwtInfo, function(err, token) {
                    if(err) {
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(err, 500);
                    }
                    else {
                        //Prepare response json
                        var responseJson = {
                            nextCall    :   nextCall+"/"+token, //TODO :: Check if token needs to be appended or send separately
                            message     :   "pass callbackUrl as query param"
                        }
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(responseJson, 302);
                    }
                });
            }
        }
    );


    // GET /auth/facebook/callback
    //   Use passport.authenticate() as route middleware to authenticate the request.
    //   On success Prepare profile data and encrypt as code.
    //   Developer has to call /account method to decrypt the code to get user account details
    app.get('/auth/facebook/callback',
        passport.authenticate('facebook', { session: false , callbackURL: '/auth/facebook/callback'}),
        function(req, res) {
            var nextCall = "/auth/complete";
            var authenticationType = "facebook";
            //Take the callbackUrl from session which is set earlier
            //var callbackUrl = (req.cookies && req.cookies.callbackUrl);

            var callbackUrl = req.query.state;

            //Prepare the profile data received after login from facebook
            var profile = {
                accessToken: req.user.accessToken,
                id: req.user.profile.id,
                displayName: req.user.profile.displayName,
                provider: req.user.profile.provider
            };

            //prepare jwt info for next completeAuthenticate call
            var jwtInfo = {
                userProfile         : profile,
                nextCall            : nextCall,
                isPosthookClear     : false,
                authenticationType  : authenticationType,
                iat                 : Math.floor(Date.now() / 1000) - 30, //TODO :: Check this if this is reqd for expiry -- backdate a jwt 30 seconds
                expiresIn           : 900
            }

            //check if callbackUrl is defined and received in state param
            if(typeof callbackUrl !== 'undefined' && callbackUrl && callbackUrl !== "undefined") {
                //encrypt the jwtInfo data as JWT token to be sent back to developer in redirection
                jwt.generateJWT(jwtInfo, function(err, token) {
                    if(err) {
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(err, 500);
                    }
                    else {
                        res.redirect(callbackUrl+'/'+token);
                    }
                });
            }
            else {
                res.header("Access-Control-Allow-Origin", "*");
                res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                res.send({error:"Not a valid redirect URL"}, 400);
            }
        }
    );
}

module.exports = facebook;

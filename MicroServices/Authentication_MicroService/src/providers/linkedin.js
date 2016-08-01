// dependencies
var passport = require('passport');
var LinkedinStrategy = require('passport-linkedin-oauth2').Strategy;
var security = require('./middleware/security');
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

// Configure the LinkedIn strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the LinkedIn API on the user's
// behalf, along with the user's profile.  The function must invoke `done`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.
if (config.configuration && config.configuration.linkedin && config.configuration.linkedin.clientID && config.configuration.linkedin.clientSecret && config.configuration.linkedin.scope) {
    passport.use(new LinkedinStrategy({
            clientID: config.configuration.linkedin.clientID,
            clientSecret: config.configuration.linkedin.clientSecret,
            //Get the scope details from VCAP
            scope: config.configuration.linkedin.scope,
            passReqToCallback: true
        },
        function(req, accessToken, refreshToken, profile, done) {
            // The function must invoke `done` with a user object, which will be set at `req.user`
            // in route handlers after authentication.(/auth/linkedin/callback will receive `req.user`)
            var user = {
                "accessToken" : accessToken,
                "refreshToken" : refreshToken,
                "profile" : profile
            };
            done(null, user);
        }
    ));
}

function linkedin(app){

    // GET /linkedin
    //   Use passport.authenticate() as route middleware to authenticate the
    //   request.  The first step in linkedin authentication will involve
    //   redirecting the user to linkedin.com.  After authorization, linkedin will
    //   redirect the user back to this application at /auth/linkedin/callback
    app.get('/linkedin/:token', [
        security.verifyLinkedin,    //verify if all required credentials available in VCAP
        security.verifyOauthRequest, //verify if callbackUrl is present in query params
        jwtVerifyPrehooks.verifyPrehooksClearanceForLinkedin //Verify the clearance for linkedin(all prehooks and authentication type)
    ], function(req,res,next) {
        passport.authenticate(
            'linkedin',{ state: req.query.callbackUrl, callbackURL: '/auth/linkedin/callback'}
        ) (req,res,next);
    });


    app.post('/auth/linkedin', [jwtVerifyPrehooks.verifyApiKey], function (req, res) {

            if ( config.prehooks && config.prehooks.linkedin) {
                var preHooks = config.prehooks.linkedin;
                var totalNoOfPrehooks = preHooks.length;
                var hookType = "prehook";
                var authenticationType = "linkedin";

                var nextCall;
                var channel = preHooks[0].channelprovider;

                if(preHooks[0].channel === 'OTP'){
                    nextCall = '/generateOtp'
                }
                if(preHooks[0].channel === 'Captcha'){
                    nextCall = '/generateCaptcha'
                }

                //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(linkedin), preparedBy(/auth/linkedin)
                var jwtInfo = {
                    totalNoOfhooks      :   totalNoOfPrehooks,
                    hooks               :   preHooks,
                    currentHook         :   1,
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
                var authenticationType = "linkedin";
                var nextCall = "/linkedin";
                //send the next method to be called is the redirection to /linkedin API with JWT token PreHooks Cleared message
                //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(linkedin), preparedBy(/auth/linkedin)
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


    // GET /auth/linkedin/callback
    //   Use passport.authenticate() as route middleware to authenticate the request.
    //   On success Prepare profile data and encrypt as code.
    //   Developer has to call /account method to decrypt the code to get user account details
    app.get('/auth/linkedin/callback',
        passport.authenticate('linkedin', { session: false , callbackURL: '/auth/linkedin/callback'}),
        function(req, res) {

            var nextCall = "/auth/complete";
            var authenticationType = "linkedin";
            //Take the callbackUrl from state which is set earlier
            var callbackUrl = req.query.state;

            //Prepare the profile data received after login from linkedin
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

module.exports = linkedin;
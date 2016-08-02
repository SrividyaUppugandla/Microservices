// dependencies
var FacebookStrategy = require('passport-facebook').Strategy;
var passport = require('passport');
var verify = require('./middleware/verify');
var authProvider = require('./middleware/auth-provider');
var scope = [];
var jwtVerifyPrehooks = require('./../jwt/verifyHooks');
var jwt = require('./../jwt/jwt');

//Read the config key value from env variables. This will return a JSON string with '=>' symbol in place of ':'
//Replace '=>' symbol with ':' to convert to JSON string and parse to retrieve JSON object
var envJson;
var config;
if(process.env.config) {
    envJson = process.env.config;
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
        verify.verifyFacebook,    //verify if all required credentials available in VCAP
        verify.verifyOauthRequest, //verify if callbackUrl is present in query params
        jwtVerifyPrehooks.verifyPrehooksClearanceForFacebook //Verify the clearance for facebook(all prehooks and authentication type)
    ], function(req,res,next) {
        passport.authenticate(
            'facebook',{ authType: 'rerequest', scope: scope ,callbackURL: '/auth/facebook/callback' , state: req.query.callbackUrl}
        ) (req,res,next);
    });


    //TODO :: This API is common for all providers... Check how to separate and use in common
    app.post('/auth/facebook', [jwtVerifyPrehooks.verifyApiKey], function (req, res) {
            var provider = "facebook";
            authProvider.authProvider(provider,function(response) {
                res.header("Access-Control-Allow-Origin", "*");
                res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                res.send(response.responseJson, response.statusCode);

            });
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
                iat                 : Math.floor(Date.now() / 1000) - 30, //backdate a jwt 30 seconds to compensate the next execution statements
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

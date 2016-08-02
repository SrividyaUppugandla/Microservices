// dependencies
var passport = require('passport');
var TwitterStrategy = require('passport-twitter').Strategy;
var verify = require('./middleware/verify');
var authProvider = require('./middleware/auth-provider');
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

// Configure the Twitter strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Twitter API on the user's
// behalf, along with the user's profile.  The function must invoke `done`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.
if (config.configuration && config.configuration.twitter && config.configuration.twitter.clientID && config.configuration.twitter.clientSecret) {
    passport.use(new TwitterStrategy({
            consumerKey: config.configuration.twitter.clientID,
            consumerSecret: config.configuration.twitter.clientSecret
        },
        function(accessToken, refreshToken, profile, done) {
            // The function must invoke `done` with a user object, which will be set at `req.user`
            // in route handlers after authentication.(/auth/twitter/callback will receive `req.user`)
            var user = {
                "accessToken" : accessToken,
                "refreshToken" : refreshToken,
                "profile" : profile
            };
            done(null, user);
        }
    ));
}

function twitter(app){

    // GET /twitter
    //   Use passport.authenticate() as route middleware to authenticate the
    //   request.  The first step in twitter authentication will involve
    //   redirecting the user to twitter.com.  After authorization, twitter will
    //   redirect the user back to this application at /auth/twitter/callback
    app.get('/twitter/:token', [
            verify.verifyTwitter,    //verify if all required credentials available in VCAP
            verify.verifyTwitterOauthRequest, //verify if callbackUrl is present in query params
            jwtVerifyPrehooks.verifyPrehooksClearanceForTwitter, //Verify the clearance for twitter(all prehooks and authentication type)
            passport.authenticate('twitter',{callbackURL: '/auth/twitter/callback'})
        ], function (req, res) {
            // The request will be redirected to Facebook for authentication, so this
            // function will not be called.
        }
    );


    app.post('/auth/twitter', [jwtVerifyPrehooks.verifyApiKey], function (req, res) {

            var provider = "twitter";
            authProvider.authProvider(provider,function(response) {
                res.header("Access-Control-Allow-Origin", "*");
                res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                res.send(response.responseJson, response.statusCode);

            });
        }
    );


    // GET /auth/twitter/callback
    //   Use passport.authenticate() as route middleware to authenticate the
    //   request.  If authentication fails, the user will be redirected back to the
    //   login page.  Otherwise, the primary route function function will be called,
    //   which, in this example, will redirect the user to the account page.
    app.get('/auth/twitter/callback',
        passport.authenticate('twitter', { callbackURL: '/auth/twitter/callback', session: false }),
        function(req, res) {

            var nextCall = "/auth/complete";
            var authenticationType = "twitter";

            //Take the callbackUrl from session which is set earlier
            //TODO :: Remove this cookie storage and change to session
            var callbackUrl = (req.cookies && req.cookies.callbackUrl);
            //Clear and expire the callbackUrl cookie
            res.clearCookie('callbackUrl');
            res.cookie("callbackUrl", "", { expires: new Date(0) });
            //var callbackUrl = req.query.state;

            //Prepare the profile data received after login from twitter
            var profile = {
                accessToken: req.user.accessToken,
                refreshToken: req.user.refreshToken,
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

            //check if callbackUrl is defined and received in from session storage
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

module.exports = twitter;

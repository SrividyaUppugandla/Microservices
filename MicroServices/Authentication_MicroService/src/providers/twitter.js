// dependencies
var passport = require('passport');
var TwitterStrategy = require('passport-twitter').Strategy;
var security = require('./middleware/security');
var config = require('./OAuth.json');
var jwtVerifyPrehooks = require('./../jwt/verifyHooks');
var jwt = require('./../jwt/jwt');

// Configure the Twitter strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Twitter API on the user's
// behalf, along with the user's profile.  The function must invoke `done`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.
if (process.env.configuration && process.env.configuration.twitter && process.env.configuration.twitter.clientID && process.env.configuration.twitter.clientSecret) {
    passport.use(new TwitterStrategy({
            consumerKey: process.env.configuration.twitter.clientID,
            consumerSecret: process.env.configuration.twitter.clientSecret
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
            security.verifyTwitter,    //verify if all required credentials available in VCAP
            security.verifyTwitterOauthRequest, //verify if callbackUrl is present in query params
            jwtVerifyPrehooks.verifyPrehooksClearanceForTwitter, //Verify the clearance for twitter(all prehooks and authentication type)
            passport.authenticate('twitter',{callbackURL: '/auth/twitter/callback'})
        ], function (req, res) {
            // The request will be redirected to Facebook for authentication, so this
            // function will not be called.
        }
    );




    app.post('/auth/twitter', [jwtVerifyPrehooks.verifyApiKey], function (req, res) {

            if ( process.env.prehooks && process.env.prehooks.twitter) {
                var preHooks = process.env.prehooks.twitter;
                var totalNoOfPrehooks = preHooks.length;
                var hookType = "prehook";
                var authenticationType = "twitter";

                var nextCall;
                var channel = preHooks[0].channelprovider;

                if(preHooks[0].channel === 'OTP'){
                    nextCall = '/generateOtp'
                }
                if(preHooks[0].channel === 'Captcha'){
                    nextCall = '/generateCaptcha'
                }

                //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(twitter), preparedBy(/auth/twitter)
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
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(err, 500);
                    }
                    else {
                        //Prepare jwt payload info json with all required values like nextcall, channel, jwt-token
                        var responseJson = {
                            nextCall            :   nextCall,
                            channelprovider     :   channel,
                            token               :   token
                        }
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(responseJson, 303);
                    }
                });
            }
            else {
                var authenticationType = "twitter";
                var nextCall = "/twitter";
                //send the next method to be called is the redirection to /twitter API with JWT token PreHooks Cleared message
                //Prepare JWT json info with totalNoOfPrehooks, preHooks object, currentPreHook(array number), authentication type(twitter), preparedBy(/auth/twitter)
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
                        res.header("Access-Control-Allow-Origin", "*");
                        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                        res.send(err, 500);
                    }
                    else {
                        //Prepare response json
                        var responseJson = {
                            nextCall    :   nextCall+"/"+token,
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
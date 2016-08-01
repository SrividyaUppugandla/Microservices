// dependencies
var fs = require('fs');
var express = require('express');
var passport = require('passport');
var path = require('path');
//TODO :: Remove this and change all config to process.env
var config = require('./providers/OAuth.json');
var app = express();

// configure Express
app.configure(function() {
    app.set('views', __dirname + '/views');
    app.set('view engine', 'jade');
    app.use(express.logger());
    app.use(express.cookieParser());
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.session({ secret: 'my_precious', maxAge: 1000*60*60 }));

    // Initialize Passport!  Also use passport.session() middleware, to support
    // persistent login sessions (recommended).
    app.use(passport.initialize());
    app.use(passport.session({maxAge: 1000*60*60}));
    app.use(app.router);
    app.use(express.static(__dirname + '/public'));

});

//Initiate provider configuration and routes.
var facebook = require('./providers/facebook');
var google = require('./providers/google');
var linkedin = require('./providers/linkedin');
var twitter = require('./providers/twitter');
var authComplete = require('./providers/auth-complete');
new authComplete(app);

//verify if all required credentials available in VCAP for Facebook and then Initiate facebook
if (process.env.configuration && process.env.configuration.facebook && process.env.configuration.facebook.clientID && process.env.configuration.facebook.clientSecret && process.env.configuration.facebook.scope) {
    new facebook(app);
}


//verify if all required credentials available in VCAP for Google and then Initiate google
if (process.env.configuration && process.env.configuration.google && process.env.configuration.google.clientID && process.env.configuration.google.clientSecret && process.env.configuration.google.scope) {
    new google(app);
}


//verify if all required credentials available in VCAP for Linkedin and then Initiate linkedin
if (process.env.configuration && process.env.configuration.linkedin && process.env.configuration.linkedin.clientID && process.env.configuration.linkedin.clientSecret && process.env.configuration.linkedin.scope) {
    new linkedin(app);
}


//verify if all required credentials available in VCAP for Twitter and then Initiate twitter
if (process.env.configuration && process.env.configuration.twitter && process.env.configuration.twitter.clientID && process.env.configuration.twitter.clientSecret) {
    new twitter(app);
}

//Hooks initiation
var otp = require('./hooks/otp.js');
var otpObj = new otp();
otpObj.generateOtp(app);
otpObj.validateOtp(app);

//Logger initiation
var logger = require('./logger/logger.js');
var loggerObj = new logger();
// created route for postLog
loggerObj.postLog(app);

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session. This would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.  However, due to the fact that this
// application does not have a database, the complete Provider(facebook/google/twitter/linkedin)
// profile along with accessToken is serialized and deserialized.
passport.serializeUser(function(user, cb) {
    cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
    cb(null, obj);
});


//Terminate an existing login session and redirect to login page.
app.get('/logout', function(req, res){
    req.logout();
    res.redirect(req.query.callbackUrl);
});

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.redirect('/login');
}

// port
var port = process.env.PORT || 3000;
app.listen(port);
console.log("Running on port :"+port);
module.exports = app;



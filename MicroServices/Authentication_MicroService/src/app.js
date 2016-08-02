// dependencies
var fs = require('fs');
var express = require('express');
var passport = require('passport');
var path = require('path');
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



//Read the config key value from env variables. This will return a JSON string with '=>' symbol in place of ':'
//Replace '=>' symbol with ':' to convert to JSON string and parse to retrieve JSON object
var envJson;
var config;
if(process.env.config) {
    envJson = process.env.config;
    envJson = envJson.replace(/=>/g, ':');
    config = JSON.parse(envJson);
}

//Initiate provider configuration and routes.

//verify if all required credentials available in VCAP for Facebook and then Initiate facebook
if (config.configuration && config.configuration.facebook && config.configuration.facebook.clientID && config.configuration.facebook.clientSecret && config.configuration.facebook.scope) {
    var facebook = require('./providers/facebook');
    new facebook(app);
}


//verify if all required credentials available in VCAP for Google and then Initiate google
if (config.configuration && config.configuration.google && config.configuration.google.clientID && config.configuration.google.clientSecret && config.configuration.google.scope) {
    var google = require('./providers/google');
    new google(app);
}


//verify if all required credentials available in VCAP for Linkedin and then Initiate linkedin
if (config.configuration && config.configuration.linkedin && config.configuration.linkedin.clientID && config.configuration.linkedin.clientSecret && config.configuration.linkedin.scope) {
    var linkedin = require('./providers/linkedin');
    new linkedin(app);
}


//verify if all required credentials available in VCAP for Twitter and then Initiate twitter
if (config.configuration && config.configuration.twitter && config.configuration.twitter.clientID && config.configuration.twitter.clientSecret) {
    var twitter = require('./providers/twitter');
    new twitter(app);
}

var authComplete = require('./providers/auth-complete');
new authComplete(app);

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



/**
 * Created by Suryakala on 24/05/16.
 */

//var express = require('express');
//var app = express();
var mongolog = require('./connectors/mongoconnector');
var graylogobj = require('./connectors/graylogconnector');
var self;

//constructor
var logger = function () {

};


var bodyParser = require('body-parser')


function initLogger(appName, userName, logStore){
    init(appName, userName, logStore);
}

function init(appName, userName, logStore){
switch(logStore){
    case 'mongoDB':
        logToMongoDB(appName);
        break;
    case 'graylog':
        logToGraylog();
        break;
    case 'splunk':
        logToSplunk();
        break;
    case 'default':
        logToMongoDB();
        break;
}
}


function logToMongoDB(appname) {
    var priority;
    var type;
    mongolog = mongolog.log(appname);
    self = {
        log: function (level, message) {
            priority = 'normal';
            type = level;
            new mongolog({datetime: Date(), priority: priority, logtype: type, msg: message}).save();
        },
        info: function (message, extra) {
            var priority = 'normal';
            var type = 'information';
            new mongolog({datetime: Date(), priority: priority, logtype: type, msg: message, extra: extra}).save(function(err){
                if(err) {
                    console.log('error: ' + err);
                }
                else{
                    console.log("Log saved on " + Date());
                }
            });
        },
        debug: function (message) {
            var priority = 'normal';
            var type = 'debug';
            new mongolog({datetime: Date(), priority: priority, logtype: type, msg: message}).save(function(err){
                if(err) {
                    console.log('error: ' + err);
                }
                else{
                    console.log("Log saved on " + Date());
                }
            });
        },
        error: function (message) {
            var priority = 'normal';
            var type = 'error';
            new mongolog({datetime: Date(), priority: priority, logtype: type, msg: message}).save(function(err){
                if(err) {
                    console.log('error: ' + err);
                }
                else{
                    console.log("Log saved on " + Date());
                }
            });
        }

    };
}


function logToGraylog(){
  var graylog = graylogobj.logger;
    self = {
        info: function (message, extra) {
            console.log('*** INFO LOGGING');
            graylog.info(message, extra, function(error, bytesSent){
                if(error){
                    console.log('*** Error Raised: '+error);
                }
                else{
                    console.log('Message sent to server  '+JSON.stringify(graylog));
                    console.log('*** Total bytes successfully delivered to Graylog server: '+bytesSent);
                }
            });
        },
        debug: function (message, extra) {
           graylog.debug(message,extra);
        },
        warning: function (message, extra) {
            graylog.warning(message,extra);
        },
        error: function (errMsg, extra) {
            graylog.error(new Error(errMsg), extra);
        },
        emergency: function (message, extra) {
            graylog.emergency(message, extra);
        },
        critical: function (message, extra) {
            graylog.critical(message, extra);
        },
        alert:  function (message, extra) {
            graylog.alert(message, extra);
        },
        notice: function (message, extra) {
            graylog.notice(message, extra);
        }

    };
}

function logToSplunk(){
  // Splunck implementation go here
}

module.exports = self;

var createLogger = function(options){
    if(options.logStore === 'graylog') {
        if (self) {
            return graylogobj.logger;
        }
        initLogger('apitestgraylog', 'admin', 'graylog');
    }
    else if(options.logStore === 'mongoDB'){
        if (self) {
            return mongolog.log;
        }
        initLogger('apitestmongo', 'surya', 'mongoDB');
    }
}

logger.prototype.postLog = function (app) {
    app.use( bodyParser.json() );       // to support JSON-encoded bodies
    app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
        extended: true
    }));

    app.post("/savelog", function (req, res) {
        var options = {logStore: 'graylog'};
        createLogger(options);

        if (!req.body.level || !req.body.message || !req.body.appid) {
            return res.send({"status": "error", "message": "missing a parameter"});
        } else {
            console.log('\n\n*** started processing!');
            var message = req.body.message;
            var extra = {appid: req.body.appid};
            var level = req.body.level.toUpperCase();
            var response;
            if (level === 'INFO' || level === 'DEBUG' || level === 'WARNING' || level === 'ERROR'
                || level === 'EMERGENCY' || level === 'ALERT' || level === 'CRITICAL' || level === 'NOTICE'
            ) {
                switch (level) {
                    case 'INFO':
                        self.info(message, extra);
                        break;
                    case 'DEBUG':
                        self.debug(message, extra);
                        break;
                    case 'WARNING':
                        self.warning(message, extra);
                        break;
                    case 'ERROR':
                        self.error(message, extra);
                        break;
                    case 'EMERGENCY':
                        self.emergency(message, extra);
                        break;
                    case 'ALERT':
                        self.alert(message, extra);
                        break;
                    case 'CRITICAL':
                        self.critical(message, extra);
                        break;
                    case 'NOTICE':
                        self.notice(message, extra);
                        break;
                }
                response = {'status': 'Success', 'message': 'Successfully sent to Graylog server'};

            }
            else {
                response = {'status': 'failed', message: 'Invalid log level'};

            }
            return res.send(response);


        }
    });
}
//
//// =======================
//// start the server ======
//// =======================
////var host = process.env.VCAP_APP_HOST || 'localhost';
//var port = process.env.PORT || 3000;
//var server = app.listen(port, function(){
//    console.log('Server running at http://localhost:'+port);
//});
//
//var closeServer = function(){
//    server.close();
//};
//
//exports.closeServer = closeServer;
//
//module.exports = app;
module.exports = logger;


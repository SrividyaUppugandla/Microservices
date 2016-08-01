var mongoose = require('mongoose');

var mongoConnection = function(appName)
{
    console.log('*** Inside mongoConnection ***');
    var persistantStoreConf = require('../configuration/config');
    var config = persistantStoreConf.mongoDB;
    var url;
    if(typeof config.server_url !== 'undefined' && config.server_url){
        var lastChar = config.server_url.slice(-1);
        if(lastChar !== '/'){
            config.server_url+'/'
        }
        url = config.server_url+appName;
    }
    else{
        var host = config.database.host;
        var port = config.database.port;
        url = 'mongodb://' + host + ':' + port + '/' + appName;
    }
    console.log('URL ' + url);


    mongoose.connect(url, function(err, db) {
        if(!err) {
            console.log("mongo connected successfully DB");
        }
        else{
            console.log("mongo connection failed");
        }
    });


    var logItemScema = new mongoose.Schema({
        priority: String,
        logtype: String,
        datetime: Date,
        msg: String,
        extra:Object
    });
    return mongoose.model('applog', logItemScema);
}


module.exports.log = mongoConnection;

/**
 * Created by Suryakala on 24/05/16.
 */

var configuration = {
    mongoDB: {
        server_urlss: "mongodb://user:pass@example.com:1234",
        database: {
            host:   'localhost',
            port:   '27017',
        },
    },
    graylog: {
        server_url: "http://54.208.196.90:12201",
        graylog_server: {
            type: 'gelf',
            host: '54.208.196.90',
            port: '12201',
            adapter:'udp',
            protocol:'udp4'
        }
    }
};
module.exports = configuration;
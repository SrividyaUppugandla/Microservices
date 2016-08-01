/**
 * Created by trujun on 26/05/16.
 */
var log = require('gelf-pro');
var persistantStoreConf = require('../configuration/config');
var config = persistantStoreConf.graylog;

log.setConfig({
    fields: {facility: "logger-service", owner: "CognizantOne"},
    adapterName: config.adapter, // currently supported "udp" only
    adapterOptions: {
        protocol: config.graylog_server.protocol, // udp adapter: udp4, udp6
        host: config.graylog_server.host,
        port: config.graylog_server.port,
    }
});


module.exports.logger = log;
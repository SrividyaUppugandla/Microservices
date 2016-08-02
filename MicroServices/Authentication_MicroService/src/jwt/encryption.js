//dependencies : Crypto module with password and encryption type
var crypto = require('crypto');
var cipherPwd = process.env.secretKey;
var encryptionType = 'aes192';

//encrypt data using crypto
exports.encryptData = function (data, callback) {
    if (data && process.env.secretKey) {
        var cipher = crypto.createCipher(encryptionType, cipherPwd);
        try {
            var encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            callback(null,encrypted);
        } catch (exception) {
            callback(exception);
        }
    }
    else {
        callback(false);
    }
};

//decrypt data using crypto
exports.decryptData = function (data, callback) {
    if (data && process.env.secretKey) {
        var decipher = crypto.createDecipher(encryptionType, cipherPwd);
        try {
            var decrypted = decipher.update(data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            callback(null,decrypted);
        } catch (exception) {
            callback(exception);
        }
    }
    else {
        callback(false);
    }
};
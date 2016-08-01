/**
 * Created by 423919 on 5/23/2016.
 * This module is used to send email
 */

var Sendmail = function () {

};

// this api will configure the sendgrid obj and send the sms
Sendmail.prototype.sendMail = function (mailObj, callback) {
    try {

        var sendgrid = require('sendgrid')(mailObj.accountSID, mailObj.authToken);
        var message = {
            "to": mailObj.toRecipient,
            "from": mailObj.fromMail,
            "subject": mailObj.subject,
            "text": mailObj.text
        };

        var email = new sendgrid.Email(message);

        sendgrid.send(email, function (error, message) {
            if (!error) {
                return callback(null, message);

            } else {
                return callback(error);
            }
        });
    }
    catch(err){
        return callback(err);
    }
}

module.exports = Sendmail;
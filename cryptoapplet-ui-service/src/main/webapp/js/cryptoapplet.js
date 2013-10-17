CryptoApplet = (function () {

    var protocol = 'http',
        host = 'localhost',
        port = 8080;

    function _getBaseUrl() {
        return protocol + '://' + host + ':' + port + '/services';
    }

    function _callSignatureService(url, params, callback) {
        $.getJSON(url, params || {}, callback).error(function (e) {
            console.log(e);
        });
    }

    return {
        API: {
            getCertificates: function (authToken, callback) {
                var baseUrl = _getBaseUrl();
                _callSignatureService(baseUrl + '/certificates?callback=?', authToken, callback);
            },

            signReference: function (authToken, format, serial, dn, inputUrl, callback) {
                var baseUrl = _getBaseUrl();
                _callSignatureService(baseUrl + '/sign/' + format + '?callback=?', {
                    appName: authToken['appName'],
                    timestamp: authToken['timestamp'],
                    signature: authToken['signature'],
                    serial: serial,
                    dn: dn,
                    inputUrl: inputUrl
                }, callback);
            }
        }
    }
})();
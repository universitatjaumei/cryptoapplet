CryptoApplet = {};

CryptoApplet.API = {

    protocol: 'http',
    host: 'localhost',
    port: 12345,

    _getBaseUrl: function () {
        return this.protocol + '://' + this.host + ':' + this.port + '/services';
    },

    _callSignatureService: function (url, params, callback, errorCallback) {
        $.getJSON(url, params || {}, callback).error(errorCallback || function (e) {
            console.log(e);
        });
    },

    getCertificates: function (callback) {
        this._callSignatureService(this._getBaseUrl() + '/certificates?callback=?', {}, callback);
    }
}
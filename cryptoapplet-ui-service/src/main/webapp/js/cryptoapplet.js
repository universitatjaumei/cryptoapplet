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
            getCertificates: function (callback) {
                var baseUrl = _getBaseUrl();
                _callSignatureService(baseUrl + '/certificates?callback=?', {}, callback);
            },

            signReference: function (format, serial, dn, inputUrl, callback) {
                var baseUrl = _getBaseUrl();
                _callSignatureService(baseUrl + '/sign/' + format + '?callback=?', {
                    serial: serial,
                    dn: dn,
                    inputUrl: inputUrl
                }, callback);
            }
        }
    }
})();

$(document).ready(function () {
    CryptoApplet.API.getCertificates(function (result) {
        var output = "";

        for (var i = 0, len = result.length; i < len; i++) {
            var certificate = result[i];

            output += '<li>';
            output += '  <a href="javascript:void(0)" class="certificate" data-format="raw" data-serial="' + certificate.serial + '" data-dn="' + certificate.dn + '">raw</a> | ';
            output += '  <a href="javascript:void(0)" class="certificate" data-format="xades" data-serial="' + certificate.serial + '" data-dn="' + certificate.dn + '">xades</a> ';
            output += certificate.dn;
            output += '</li>';
        }

        $('#certificateList').html("<ul>" + output + "</ul>");

        $('.certificate').click(function (link) {
            var format = $(this).attr('data-format');
            var serial = $(this).attr('data-serial');
            var dn = $(this).attr('data-dn');
            var inputUrl = $('#inputUrl').val();

            CryptoApplet.API.signReference(format, serial, dn, inputUrl, function (result) {
                console.log(result);

                $.base64.utf8encode = true;
                $('#signatureResult').val($.base64.atob(result.data, true));
            });
        });
    });
});
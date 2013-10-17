$(document).ready(function () {
    CryptoApplet.API.getCertificates(authToken, function (result) {
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

            CryptoApplet.API.signReference(authToken, format, serial, dn, inputUrl, function (result) {
                console.log(result);

                $.base64.utf8encode = true;
                $('#signatureResult').val($.base64.atob(result.data, true));
            });
        });
    });
});
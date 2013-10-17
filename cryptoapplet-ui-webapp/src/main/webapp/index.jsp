<%@ page import="es.uji.apps.cryptoapplet.ui.auth.TokenGenerator" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html>
<html>
  <head>
    <script src="//localhost:8080/js/jquery-1.9.1.js"></script>
    <script src="//localhost:8080/js/jquery.base64.js"></script>
    <script src="//localhost:8080/js/cryptoapplet.js"></script>
    <script src="js/cryptoapplet-client.js"></script>

    <%
        String appName = "APA";
        String timestamp = String.valueOf(new Date().getTime());

        String tokenData = String.format("%s:%s", appName, timestamp);

        TokenGenerator tokenGenerator = new TokenGenerator();
        String signature = tokenGenerator.generateToken(tokenData);
    %>

    <script>
        var authToken = {
          appName: '<%= appName %>',
          timestamp: '<%= timestamp %>',
          signature: '<%= signature %>'
        }
    </script>
  </head>

  <body>
    <h1>CryptoApplet API</h1>

    <h2>Certificate list</h2>
    <div id="certificateList"></div>

    <h2>Data to sign</h2>
    <input id="inputUrl" type="text" size="40" value="http://localhost:8081/rest/data">

    <h2>Signature result</h2>
    <textarea id="signatureResult" rows="10" style="width:100%;"></textarea>
  </body>
</html>
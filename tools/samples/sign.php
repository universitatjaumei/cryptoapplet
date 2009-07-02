<html>
<head>
<title>
Pruebas applets.
</title>
</head>
<body>
<br><br>


<form name="signedForm" method="post" action="show.php">

<input type="hidden" name="message">
<input type="hidden" name="result">
<input type="hidden" name="text" value="GiznxohI+54W+FavHSNZTpe+Qsk=">

</form> 


<script language="javascript">
function getAgent(){
//alert(document.getElementsByName("CryptoApplet").length);
//document.getElementByiId('browser');//= navigator.userAgent;
return navigator.userAgent;
}

function onInitOk(){
 alert("First Java-to-Javascript invocation");
 document.getElementById("CryptoApplet").style.width=0;
 document.getElementById("CryptoApplet").style.height=0;
}

function onSignOk(signature){
 
 alert(signature);
 
 //document.getElementById('sig').innerHTML=signature;
}

function onSignError(errorDesc){
  alert("ERROR: " + errorDesc);
}

function onSignCancel(){
  alert("User Canceled");
}

function clean(){
  document.getElementById("vfy").innerHTML= "";
}

function verify(){
  var res= document.CryptoApplet.verifyXAdESDataUrl("http://lab9083.act.uji.es/~paul/test/xml/sig.xml"); 
  alert(res);
  document.getElementById("vfy").innerHTML= res[0];
}

function testApplet(){
  document.CryptoApplet.setInputDataEncoding("PLAIN");
  document.CryptoApplet.setSignatureOutputFormat("CMS_HASH");
  document.CryptoApplet.testSetup(document.getElementById('appletDiv').innerHTML,"","");
  document.CryptoApplet.doTest();
} 


function Sign(){
  //CMS
  try{ 
    var cp= document.getElementById("CryptoApplet");
    cp.setInputDataEncoding("HEX");
    cp.setSignatureOutputFormat("CMS_HASH");
    cp.signDataParamToURL("11f6ad8ec52a2984abaafd7c3b516503785c2072","http://lab9083.act.uji.es/~paul/test/v2.1/write.php");
  }
  catch(e){
    alert(e.message);
  }
}

</script>
<br><br><br>

<form name="form" method="post" action="show.php">
  <input type="hidden" name="message" value="a">
  <input type="hidden" name="result" value="a">
  <input type="button" value="Sign" onClick="Sign();">
  <input type="button" value="Test" onClick="testApplet();">
  <input type="button" value="Verify" onClick="verify();">
  <input type="button" value="Clean" onClick="clean();">

</form>

</script>
<div id="sig"></div>
<div id="vfy"></div>
<div id="appletDiv">
<applet 
    id="CryptoApplet" 
    name="CryptoApplet" 
    code="es.uji.security.ui.applet.SignatureApplet" 
    width="200" height="200" 
    codebase="app/"
    archive="uji-ui-applet-2.1.0-signed.jar,
	     uji-config-2.1.0-signed.jar,
             uji-crypto-raw-2.1.0-signed.jar,
 	     uji-crypto-cms-2.1.0-signed.jar,
	     uji-crypto-xmldsign-2.1.0-signed.jar,
	     uji-utils-2.1.0-signed.jar,
	     uji-crypto-core-2.1.0-signed.jar,
	     uji-format-pdf-2.1.0-signed.jar,
 	     uji-crypto-openxades-2.1.0-signed.jar,
	     uji-keystore-2.1.0-signed.jar,
	     jakarta-log4j-1.2.6.jar,
	     bcprov-jdk15-143.jar,
	     bcmail-jdk15-143.jar,
	     bctsp-jdk15-143.jar		
	    "	 
    mayscript>
</applet>
</div>
</body>

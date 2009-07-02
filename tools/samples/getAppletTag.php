<?
  $av="2.1.0";

  $jakarta="jakarta-log4j-1.2.6.jar";
  $bcprov="bcprov-jdk15-143.jar";
  $bcmail="bcmail-jdk15-143.jar";
  $bctsp="bctsp-jdk15-143.jar"; 
  $itext="itext-1.4.8.jar"; 
  $jxades="jxades-1.0.jar"; 
  $xalan="xalan-2.7.0.jar";

  //CryptoApplet construction tag WebService.
  $outputFor= htmlentities($_REQUEST['outputfor']);

?>

<applet
    id="CryptoApplet"
    name="CryptoApplet"
    code="es.uji.security.ui.applet.SignatureApplet"
    width="200" height="200"
    codebase="app/"
    archive="uji-ui-applet-<?echo $av;?>-signed.jar,
             uji-config-<?echo $av;?>-signed.jar,
             uji-utils-<?echo $av;?>-signed.jar,
             uji-crypto-core-<?echo $av;?>-signed.jar,
             uji-keystore-<?echo $av;?>-signed.jar,
             <?echo $jakarta;?>,
<?

switch($outputFor){
case 'CMS_HASH':
case 'CMS':
?>
           uji-crypto-cms-<?echo $av;?>-signed.jar, 
           <?echo $bcprov;?>,
           <?echo $bcmail;?>,
           <?echo $bctsp;?>,                
<? 
  break;
  case 'FACTURAE':
             echo $jxades . ",";
             echo $xalan . ",";
  break;
  case 'PDF':
?>
             uji-format-pdf-<?echo $av;?>-signed.jar,
             uji-crypto-cms-<?echo $av;?>-signed.jar, 
             <?echo $itext;?>,
             <?echo $bcprov;?>,
             <?echo $bcmail;?>,
             <?echo $bctsp;?>"
<?

  break;
  case 'XMLDSIG':
?>
           uji-crypto-xmldsign-<?echo $av;?>-signed.jar,
<?
  break;
  case 'XADES':
?>
           uji-crypto-openxades-<?echo $av;?>-signed.jar,
           xmlsec.jar,
           myxmlsec.jar,
           xalan.jar,
           commons-logging.jar,
           <?echo $bcprov;?>,
           <?echo $bcmail;?>,
           <?echo $bctsp;?>,
<?
  break;  
  default: 
?>
             uji-crypto-raw-<?echo $av;?>-signed.jar,
<?
 }
?>
 "
 mayscript>
  </applet>


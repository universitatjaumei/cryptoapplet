var ch= false;
var test= false;
var xadesBigFile=false;

function notifySuccess(txt){
  $("#greenDiv").html(txt);
  $.notifyBar({
    delay: 2000,
    animationSpeed: "normal",
    jqObject: $("#greenDiv")
  });  
}

function notifyError(txt){
  $("#errorDiv").html(txt);
  $.notifyBar({
    delay: 4000,
    animationSpeed: "normal",
    jqObject: $("#errorDiv")
  });
}


function myconsole(m){
 // if (typeof(console)!="undefined"){
 //   console.log(m);
 // }
 //alert(m);
}

function onWindowShow(){
  //pass
}

function onSignCancel() {
  notifyError('Signature process cancelled');
}

function onSignOk(txt){ 
 
  var fmat= $('input[name="format"]');
  for(i=0; i<fmat.length; i++){
     if (fmat[i].checked){
        outputFor= fmat[i].id.toUpperCase();
     }
  }

  if (outputFor=="XADES" && txt == null){
    document.location.assign(document.location.href.replace("test.html","signature.xsig"));
    document.getElementById("btnvfy").disabled= false;
    return;
  }
 
  if (outputFor=="PDF"){
    document.location.assign(document.location.href.replace("test.html","signed.pdf"));  
    document.getElementById("btndwn").disabled= false;
  }
  else{
    document.getElementById("sigta").value=txt;
    document.getElementById("sigta").style.visibility="visible";
    document.getElementById("btnl").disabled= false;
 
    if (outputFor=="XADES")
      document.getElementById("btnvfy").disabled= false;
  }
  
  if ( outputFor=="FACTURAE" ){
    document.getElementById("btndwn").style.visibility="visible";

    document.getElementById("btndwn").disabled= false;
    document.getElementById("btnvfy").disabled= true;
    document.getElementById("info").innerHTML="<img align='left' src='img/alerticon.jpg' />You can verify the invoice by downloading it and uploading to <a target='_blank' href='http://www11.mityc.es/FacturaE/index.jsp'> mityc e-invoice validation service </a>";
  }
  
  notifySuccess("Signature for format " + outputFor + " has been done Ok!"); 

}

//TODO: Correct that function, the url must be calculated from the document.location.
function verifyXAdES(){
  $.post("write_b64.php","content=" + $.URLEncode($.base64Encode(document.getElementById("sigta").value)));
  var cp= document.getElementById("CryptoApplet");
  var r= cp.verifyXAdESDataUrl(document.location.href.replace("test.html","signature.xsig"));
  if (r==null || r.length==0 )
    notifySuccess("OK");
  else
    notifyError(r[0]);
}

function downloadTextArea(){
 $.post(
         "write_b64.php",
         "content=" + $.URLEncode($.base64Encode(document.getElementById("sigta").value)),
         function(data){
           document.location="get.php";
         }
       );
}


function onSignError(txt){
  notifyError("Error:  " + txt);
  document.getElementById("btnl").disabled= true;
}

function Sign(){
  var enc= $('input[name="encoding"]');
  var inputEnc="";

  var oenc= $('input[name="output_encoding"]');
  var outputEnc="";
  
  var xopts= $('input[name="xopts"]');
  var lang= $('input[name="lang"]');
  
  var fmat= $('input[name="format"]');
  var outputFor="";

  var cp= document.getElementById("CryptoApplet");
  var loc= document.location.href;

  //Disable sign and load buttons till something happens
  document.getElementById("btns").disabled= true;
  document.getElementById("btnl").disabled= true;

  //try{ 

    if (!cp){
      notifyError("ERROR: getting the applet object from tag id Cryptoapplet");
      return; 
    }


    for(i=0; i<fmat.length; i++){
      if (fmat[i].checked){
        outputFor= fmat[i].id.toUpperCase();
        cp.setSignatureOutputFormat(outputFor);
      }
    }

    for(i=0; i<lang.length; i++){
      if (lang[i].checked){
        cp.setLanguage(lang[i].id);
      }
    }


    for(i=0; i<enc.length; i++){
      if (enc[i].checked){
        inputEnc= enc[i].value.toUpperCase();
        cp.setInputDataEncoding(inputEnc);
      }
    }

   for(i=0; i<oenc.length; i++){
      if (oenc[i].checked){
        outputEnc= oenc[i].value.toUpperCase();
        cp.setOutputDataEncoding(outputEnc);
      }
    }


    myconsole("outputFor: " + outputFor);
    if (outputFor=="XADES"){

      var aux= document.getElementById("srole");
      if (aux){
        myconsole("role set to: " + jQuery.trim(aux.value));
        cp.setXadesSignerRole(jQuery.trim(aux.value));  
      }

      aux= document.getElementById("fname");
      if (aux){
        myconsole("File name set to: " + jQuery.trim(aux.value));
        cp.setXadesFileName(jQuery.trim(aux.value));  
      }
      
      aux= document.getElementById("fmime");
      if (aux){
        myconsole("File mime type to: " + jQuery.trim(aux.value));
        cp.setXadesFileMimeType(jQuery.trim(aux.value));  
      }
    }
    aux= document.getElementById('ts');
    if (aux || outputFor=="PDF" || outputFor=="FACTURAE" || outputFor=="XADES" && xadesBigFile){
      if (outputFor=="XMLSIGNATURE"){
        if (! aux.value.match("^<[^>]+>[^<]*<[^>]+>$")){
          notifyError("ERROR: The content for XMLSIGNATURE must be an XML, please enclose it with, for example: &lt;data&gt;content&lt;/data&gt; ");
          document.getElementById("sigta").style.visibility="visible";
          document.getElementById("btnl").disabled= false;
          return;
        }
      } 
      if (outputFor=="XADES" && xadesBigFile){
         cp.setIsBigFile("true"); 
         cp.signDataUrlToUrl(loc.replace("test.html","fich/bigf.bin") , loc.replace("test.html","write.php"));
         return;
      }
      if (inputEnc=="HEX"){
        if (!aux.value.match("^([0-9a-fA-F][0-9a-fA-F])+$")){
          notifyError("ERROR: The input data is not a valid HEX value");
          document.getElementById("sigta").style.visibility="visible";
          document.getElementById("btnl").disabled= false;
          return;
        }
      }

      if (outputFor=="PDF"){
         myconsole("Let's invoke the function cp.signUrlToUrl for a PDF");
         myconsole("input:" + loc.replace("test.html","fich/f1.pdf"));
         myconsole("output:" + loc.replace("test.html","write_pdf.php"));

         cp.setOutputDataEncoding("BASE64");
         cp.signDataUrlToUrl(loc.replace("test.html","fich/f1.pdf") , loc.replace("test.html","write_pdf.php"));
      }
      else if(outputFor=="FACTURAE"){
         notifySuccess("Facturae format selected");
         cp.signDataUrlToFunc(loc.replace("test.html","factura.xml") , "onSignOk");
      }
      else{
         myconsole("Let's invoke the function cp.signDataParamToFunc: " + jQuery.trim(aux.value));
         //TODO: descomentar esto, es solo para XADES.
         cp.signDataParamToFunc(aux.value, "onSignOk");
         //alert("Aux: " + aux.value);
         //cp.signDataParamToUrl(aux.value, loc.replace("test.html","write.php")); //"onSignOk");
         myconsole("Invoked!");
      }
    }
    else{
      notifyError("ERROR: cannot get data for signature");
    }
  //} 
  //catch(e) {
  //  alert("Por favor, reinicie su navegador, \nparece que hubo un problema en la aplicacion, \nsi ya lo ha hecho pongase en contacto con un administrador.\n\nERROR: " + e.message);
 // }
}



function onInitOk(){
  cp= document.getElementById("CryptoApplet");
  if (test){
    notifySuccess("The java version is: " +  cp.getJavaVersion());
    document.getElementById("gjv").disabled=false;
    test= false; 
  }
  else{
    notifySuccess("The applet has been correctly loaded.");
    document.getElementById("btns").disabled= false;
  }
  document.getElementById("cappd").style.visibility= "hidden";
  document.getElementById("btnl").disabled= false;
}

function selectText(v){
  x= document.getElementById(v);
  x.focus();
  x.select();
}

function handleCheck(v){
//  document.getElementById('xopts').innerHTML="";
  if (document.getElementById(v).checked){
    document.getElementById('sigContent').innerHTML="";
    ch=true;
    xadesBigFile=true;
  }
  else{
    xadesBigFile=false;
  }
}

function handleRadio(v){

  xadesBigFile=false;

  if ( v=='xades' && document.getElementById('xades').checked )
  {
    $("#xopts").load("xopts.html");
    document.getElementById('popts').innerHTML="";
    if (ch){
     document.getElementById('sigContent').innerHTML='<textarea id="ts" onClick="selectText(\'ts\');" \
        style="border: thin solid rgb(50,205,50);" cols="100" rows="10">\
        Escribe aquí el contenido a firmar.\
        </textarea>';
      ch=false;
    }
  }
  else if ( v=='pdf' && document.getElementById('pdf').checked )
  {
    document.getElementById('xopts').innerHTML="";
    document.getElementById('sigContent').innerHTML="";
    $("#popts").load("pdf.php");  
    ch=true;
  }
  else if (v=='facturae'){
     document.getElementById('xopts').innerHTML="";
     document.getElementById('sigContent').innerHTML='<div id="info" style="width: 60%; border: thin solid rgb(50,205,50);">You can download the invoice it is going to be signed from here: <a href="factura.xml"> INVOICE</a></div>';
     ch=true;
     //alert("Format not implemented yet, please try another one");
     //document.getElementById('raw').checked=true;
  }
  else
  {
    document.getElementById('xopts').innerHTML="";
    if (ch){
      document.getElementById('popts').innerHTML="";
      document.getElementById('sigContent').innerHTML='<textarea id="ts" onClick="selectText(\'ts\');" \
        style="border: thin solid rgb(50,205,50);" cols="100" rows="10">\
        Escribe aquí el contenido a firmar.\
        </textarea>';
      ch=false;      
    } 
  }  
}

function enable(btid){
  document.getElementById(btid).disabled=false;
}

function testJavaVersion(){
 document.getElementById("cappd").style.visibility="visible";
 document.getElementById("gjv").disabled=true;
 document.getElementById("btnl").disabled=true;
 test= true;
 jQuery.post("getAppletTag.php", "&test=true", function(data, textStatus){ $('#cappd').attr("innerHTML",data);} );
}

function loadApplet(){
  
  var fmat= $('input[name="format"]');
  var outputFor="";
  var param="a=b";

  //Disable load button during operation: 
  document.getElementById("btnl").disabled=true;
  document.getElementById("sigta").value="";
  document.getElementById("sigta").style.visibility="hidden";
  document.getElementById("cappd").style.visibility= "visible";

  setTimeout("enable('btnl');",2000);
 
  for(i=0; i<fmat.length; i++){
    if (fmat[i].checked){
      outputFor= fmat[i].id.toUpperCase();
      param +="&outputfor=" + outputFor;  
    }
  }

  jQuery.post("getAppletTag.php", param, function(data, textStatus){ $('#cappd').attr("innerHTML",data);} );

}


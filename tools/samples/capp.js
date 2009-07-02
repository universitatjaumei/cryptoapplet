var ch= false;
var test= false;

function myconsole(m){
 // if (typeof(console)!="undefined"){
 //   console.log(m);
 // }
 alert(m);
}

function onSignOk(txt){

  var fmat= $('input[name="format"]');
  for(i=0; i<fmat.length; i++){
     if (fmat[i].checked){
        outputFor= fmat[i].id.toUpperCase();
        cp.setSignatureOutputFormat(outputFor);
     }
  }

  if (outputFor=="PDF"){
    document.location.assign(document.location.href.replace("test.html","signed.pdf"));  
  }
  else{
    document.getElementById("sigta").value=txt;
    document.getElementById("sigta").style.visibility="visible";
    document.getElementById("btnl").disabled= false;
    document.getElementById("btnvfy").disabled= false;
  }
}

//TODO: Correct that function, the url must be calculated from the document.location.
function verifyXAdES(){
  alert(document.location);
  $.post("write.php","content=" + $.URLEncode(document.getElementById("sigta").value));
  var cp= document.getElementById("CryptoApplet");
  var r= cp.verifyXAdESDataUrl(document.location.href.replace("test.html","signature.xdsig"));
  if (r!=null)
    alert(r[0]);
  else
    alert("OK");
}

function onSignError(txt){
  alert("Error:  " + txt);
  document.getElementById("btnl").disabled= true;
}

function Sign(){
  var enc= $('input[name="encoding"]');
  var inputEnc="";

  var xopts= $('input[name="xopts"]');
  var lang= $('input[name="lang"]');
  
  var fmat= $('input[name="format"]');
  var outputFor="";

  var cp= document.getElementById("CryptoApplet");


  //Disable sign and load buttons till something happens
  document.getElementById("btns").disabled= true;
  document.getElementById("btnl").disabled= true;

  try{ 

    if (!cp){
      alert("ERROR: getting the applet object from tag id Cryptoapplet");
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
        inputEnc= enc[i].id.toUpperCase();
        cp.setInputDataEncoding(inputEnc);
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
    if (aux || outputFor=="PDF"){
      if (outputFor=="XMLDSIG"){
        if (! aux.value.match("^<[^>]+>[^<]*<[^>]+>$")){
          alert("ERROR: The content for XMLDSIG must be an XML, \nplease enclose it with, for example:\n   <data></data> ");
          document.getElementById("sigta").style.visibility="visible";
          document.getElementById("btnl").disabled= false;
          return;
        }
      } 
      if (inputEnc=="HEX"){
        if (!aux.value.match("^([0-9a-fA-F][0-9a-fA-F])+$")){
          alert("ERROR: The input data is not a valid HEX value");
          document.getElementById("sigta").style.visibility="visible";
          document.getElementById("btnl").disabled= false;
          return;
        }
      }

      if (outputFor=="PDF"){
         var loc= document.location.href;
         
         myconsole("Let's invoke the function cp.signUrlToUrl for a PDF");
         myconsole("input:" + loc.replace("test.html","fich/f1.pdf"));
         myconsole("output:" + loc.replace("test.html","write_pdf.php"));

         cp.setOutputDataEncoding("BASE64");
         cp.signDataUrlToUrl(loc.replace("test.html","fich/f1.pdf") , loc.replace("test.html","write_pdf.php"));
      }
      else{
         myconsole("Let's invoke the function cp.signDataParamToFunc: " + jQuery.trim(aux.value));
         cp.signDataParamToFunc(aux.value, "onSignOk");
      }
    }
    else{
      alert("ERROR: cannot get data for signature");
    }
  } 
  catch(e) {
    alert("Por favor, reinicie su navegador, \nparece que hubo un problema en la aplicacion, \nsi ya lo ha hecho pongase en contacto con un administrador.\n\nERROR: " + e.message);
  }
}



function onInitOk(){
  cp= document.getElementById("CryptoApplet");
  if (test){
    alert("The java version is: " +  cp.getJavaVersion());
    document.getElementById("gjv").disabled=false;
    test= false; 
  }
  else{
    alert("The applet has been correctly loaded.");
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

function handleRadio(v){
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
     alert("Format not implemented yet, please try another one");
     document.getElementById('raw').checked=true;
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


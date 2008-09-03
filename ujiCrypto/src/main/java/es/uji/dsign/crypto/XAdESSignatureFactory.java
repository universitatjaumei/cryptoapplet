package es.uji.dsign.crypto;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Properties;

import java.net.URL;
import java.net.URLConnection;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.net.SocketTimeoutException;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import es.uji.dsign.crypto.digidoc.CertValue;
import es.uji.dsign.crypto.digidoc.DataFile;
import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.Signature;
import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.TimestampInfo;
import es.uji.dsign.crypto.digidoc.utils.ConfigManager;
import es.uji.dsign.util.i18n.LabelManager;
import es.uji.dsign.util.Base64;
import es.uji.dsign.util.ConfigHandler;


public class XAdESSignatureFactory extends AbstractSignatureFactory implements ISignFormatProvider
{
    private Logger log = Logger.getLogger(XAdESSignatureFactory.class);
    private String _strerr= "";
    private static int CONN_TIMEOUT= 5000;
    private String signerRole= "UNSET";
    private String xadesFileName= "data.xml";
	private String xadesFileMimeType="application/binary";
    
    public void setSignerRole(String srole)
    {
    	signerRole= srole;
    }
    
    public void setXadesFileName(String filename)
    {
    	xadesFileName= filename;
    }
    
    public void setXadesFileMimeType(String fmimetype) {
		xadesFileMimeType = fmimetype;
		
	}
    
	public byte[] formatSignature(byte[] toSign, X509Certificate sCer, PrivateKey pk, Provider pv) throws Exception
	{		
		// Inicializamos el registro de proveedores
		
		super.initProviderList();
				
		/*for ( Enumeration enu= ksh.aliases();  enu.hasMoreElements(); ){
			System.out.println("Next elem: " + enu.nextElement());	
		}*/
		
		log.debug("Using XAdESSignatureFactory");
		log.debug(pv.getName() + " provider found");
				
		Properties prop= ConfigHandler.getProperties();
		if ( prop != null ){
			ConfigManager.init(prop);
		}
		else{
			_strerr= LabelManager.get("ERROR_DDOC_NOCONFIGFILE");
			return null;
		}
				
		// Creamos un nuevo SignedDoc XAdES
		SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
		// Añadimos una nueva referencia de fichero en base64 ... aunque establecemos el body 
		DataFile df = sdoc.addDataFile(new File("jar://data.xml"), "application/binary", DataFile.CONTENT_EMBEDDED_BASE64);		
		
		System.out.println("Seleccionando nombre fichero a: " + xadesFileName);
		sdoc.getDataFile(0).setFileName(xadesFileName);		
		sdoc.getDataFile(0).setMimeType(xadesFileMimeType);		
		
		df.setBody(toSign);
		df.setSize(toSign.length);
		
		return signDoc(sdoc, toSign, sCer, pk, pv);
	}

	protected byte[] signDoc( SignedDoc sdoc, byte[] toSign, X509Certificate sCer, PrivateKey pk, Provider pv )
	throws Exception{
						
              
        if (sCer == null)
        {
      		_strerr= LabelManager.get("ERROR_DDOC_NOCERT");
			return null;
        }
       
                  
		if ( pk == null ){
			_strerr= LabelManager.get("ERROR_DDOC_NOKEY");
			return null;
		}
		
				
		//Prepare the signature
		//TODO: Role support in the signature
		Signature sig = sdoc.prepareSignature((X509Certificate) sCer, new String[] { signerRole }, null);
				
		//Do the signature
		byte[] sidigest= sig.getSignedContent();
		if ( sidigest == null ){
			_strerr= LabelManager.get("ERROR_DDOC_NODIGEST");
			return null;
		}
				
		java.security.Signature rsa = java.security.Signature.getInstance("SHA1withRSA", pv);
		rsa.initSign(pk);
		rsa.update(sidigest);
		byte[] res = rsa.sign();
		
		if ( res == null ){
			log.error("No se pudo calcular la firma");
			_strerr= LabelManager.get("ERROR_DDOC_SIGNATURE");
			return null;
		}

		log.debug("Signing XAdES info. XAdES signature length " + res.length);

		 //Add the signature to the signed doc
		sig.setSignatureValue(res);
		 
		//Get the timestamp and add it  
		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

		// Request TSA to return certificate
		reqGen.setCertReq(false);
		
		SHA1Digest sha = new SHA1Digest();
		sha.engineUpdate(sig.getSignatureValue().toString().getBytes(),0,
						 sig.getSignatureValue().toString().length());
		
		byte[] hash = sha.engineDigest();
		if ( hash == null ){
			_strerr= LabelManager.get("ERROR_DDOC_TSDIGEST");
			return null;	
		}
				
		
		String tsaUrl= ConfigManager.instance().getProperty("DIGIDOC_TSA1_URL");
		byte[] asn1Resp= TimeStampFactory.getTimeStamp(tsaUrl, hash);
		
		if ( asn1Resp == null ){
			_strerr= LabelManager.get("ERROR_DDOC_TSATIMEOUT");
    	 	return null;
		}
				
		TimeStampResponse tsr= new TimeStampResponse(asn1Resp);
		
     	TimestampInfo ts = new TimestampInfo("TS1", TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
		ts.setTimeStampResponse(tsr);		
		ts.setSignature(sig);
		
		TimeStampToken ttk= tsr.getTimeStampToken();
		if ( ttk == null ){
			_strerr= LabelManager.get("ERROR_DDOC_TSARESPONSE");
			return null;
		}
		
		TimeStampTokenInfo tstki= ttk.getTimeStampInfo();
		if ( tstki == null ){
			_strerr= LabelManager.get("ERROR_DDOC_TSARESPONSE");
			return null;
		}
		
		byte[] msgdig= tstki.getMessageImprintDigest();
		if ( msgdig == null ){
			_strerr= LabelManager.get("ERROR_DDOC_TSARESPONSE");
			return null;
		}
		
		ts.setHash(msgdig);
		
		sig.addTimestampInfo(ts);
		
		String tsa1_ca= ConfigManager.instance().getProperty("DIGIDOC_TSA1_CA_CERT");
		if ( tsa1_ca == null ){
			_strerr= LabelManager.get("ERROR_DDOC_TSACA");
			return null;
		}
		
		X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);
		
		CertValue cval = new CertValue();
        cval.setType(CertValue.CERTVAL_TYPE_TSA);
        cval.setCert(xcaCert);
        cval.setId(sig.getId() + "-TSA_CERT");
        
   
        try 
		{
        	//Añadimos certificado TSA 
	        sig.addCertValue(cval);        
	        
	        // Verificación OCSP
	        if (ConfigManager.instance().getProperty("DIGIDOC_CERT_VERIFIER").trim().equals("OCSP")){
	        	sig.getConfirmation();
	        }
	        
			log.debug("Verificación OCSP completa");
		} 
		catch (DigiDocException e) 
		{
			if ( e.getCode() == e.ERR_CERT_REVOKED ){
				_strerr= LabelManager.get("ERROR_DDOC_CERTREVOKED");
			}		
			else if ( e.getCode() == e.ERR_CERT_EXPIRED ){
				_strerr= LabelManager.get("ERROR_DDOC_CERTEXPIRED");
			}
			else if ( e.getCode() == e.ERR_CA_CERT_READ ){ 
				_strerr= LabelManager.get("ERROR_DDOC_CERT_NOT_ALLOWED");
				//_strerr= LabelManager.get("ERROR_DDOC_CACERTREAD");
			}
			else if ( e.getCode() == e.ERR_OCSP_READ_FILE || e.getCode() == e.ERR_OCSP_ISSUER_CA_NOT_FOUND ){ 
				_strerr= LabelManager.get("ERROR_DDOC_CERT_NOT_ALLOWED");
			}
			else{ 
				_strerr= LabelManager.get("ERROR_DDOC_CERTGENERIC");			
			}
			log.debug("\n\n" + this.getClass().getName() + ": No se pudo realizar la confirmacion OCSP" + e.getMessage());
			//e.printStackTrace();
			return null;
		}
	
		
       	// Devolvemos el documento firmado y codificado
		return Base64.encode(sdoc.toXML().getBytes(),true);
	}
	
	public String getError(){
		return _strerr;
	}
}
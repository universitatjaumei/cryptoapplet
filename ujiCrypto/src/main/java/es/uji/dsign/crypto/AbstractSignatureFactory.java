package es.uji.dsign.crypto;

import java.security.Security;
import java.util.Hashtable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public abstract class AbstractSignatureFactory
{
	public static Hashtable<String,String> formatImplMap= null;
	
	/* Valid formats */
	public static String SIGN_FORMAT_RAW          = "RAW";
	public static String SIGN_FORMAT_CMS          = "CMS";
	public static String SIGN_FORMAT_XADES        = "XADES";
	public static String SIGN_FORMAT_XADES_COSIGN = "XADES_COSIGN";
	public static String SIGN_FORMAT_PDF          = "PDF";
	public static String SIGN_FORMAT_XMLDSIG      = "XMLDSIG";
	public static String SIGN_FORMAT_FACTURAE	  = "FACTURAE";

	
	/**
	 * That types of signatures are allowed for set up in function 
	 * setSignatureOutputFormat(String format);
	 **/		
	public static String[] formats= new String[]{
												 "RAW",
												 "CMS",
												 "CMS_HASH",
												 "XADES",
												 "XADES_COSIGN",
												 "PDF",							 
												 "XMLDSIG",
												 "FACTURAE"
												 };
	
	/**
	 * That are the mappings between the allowed formats and the 
	 * classes that implements it.  
	 **/
	public static String[] impls= new String[] {
												 "es.uji.dsign.crypto.RawSignatureFactory",
												 "es.uji.dsign.crypto.CMSSignatureFactory",
												 "es.uji.dsign.crypto.CMSHashSignatureFactory",
												 "es.uji.dsign.crypto.XAdESSignatureFactory",
												 "es.uji.dsign.crypto.XAdESCoSignatureFactory",
												 "es.uji.dsign.crypto.PDFSignatureFactory",
												 "es.uji.dsign.crypto.XMLDsigSignatureFactory",
												 "es.uji.dsign.crypto.FacturaeSignatureFactory"
												};                                 
	
	
	public static Hashtable<String,String> getFormatImplMapping(){
		if (formatImplMap==null){
			formatImplMap= new Hashtable<String,String>();
			for (int i=0; i< formats.length; i++)
				formatImplMap.put(formats[i], impls[i]);
				
		}
		return formatImplMap;
	}
	
	public void initProviderList()
	{
		if (Security.getProvider("BC") == null)
		{
			BouncyCastleProvider bcp = new BouncyCastleProvider();
			Security.addProvider(bcp);
		}
	
		if (Security.getProvider("UJI-MSCAPI") == null)
		{
			MSCAPIProvider uji = new MSCAPIProvider();
			Security.addProvider(uji);
		}
	}
}
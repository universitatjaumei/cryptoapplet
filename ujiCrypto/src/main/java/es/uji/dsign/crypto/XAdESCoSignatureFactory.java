package es.uji.dsign.crypto;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.factory.DigiDocFactory;
import es.uji.dsign.crypto.digidoc.utils.ConfigManager;
import es.uji.dsign.crypto.keystore.IKeyStoreHelper;


public class XAdESCoSignatureFactory  extends AbstractSignatureFactory implements ISignFormatProvider {

	private String signerRole= "UNSET";
	private String _sterr= "";

	public void setSignerRole(String srole)
	{
		signerRole= srole;
	}
	
	public byte[] formatSignature( byte[] toSign, X509Certificate sCer, PrivateKey pk, Provider pv )
	throws Exception {
		
		byte[] res;

		String BASE = "jar://"; 
		ConfigManager.init(BASE + "jdigidoc.cfg");

		DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
		SignedDoc sdoc = digFac.readSignedDoc(new ByteArrayInputStream(toSign));
				
		XAdESSignatureFactory xsf= new XAdESSignatureFactory();
		xsf.setSignerRole(signerRole);
		
		res= xsf.signDoc(sdoc, toSign, sCer, pk, pv);
		
		_sterr=  xsf.getError();
						
		return res;
	}

	public String getError() {
		return _sterr;
	}
}

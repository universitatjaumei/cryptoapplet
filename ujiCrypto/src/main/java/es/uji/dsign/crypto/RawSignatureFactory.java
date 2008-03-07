package es.uji.dsign.crypto;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.security.Signature;
import es.uji.dsign.util.i18n.LabelManager;

public class RawSignatureFactory  extends AbstractSignatureFactory implements ISignFormatProvider {
	private String _strerr= "";
		
	public byte[] formatSignature(byte[] datos, X509Certificate sCer, PrivateKey pk, Provider pv) throws KeyStoreException, Exception
	{
		
		System.out.println("Entro!");
		
		Signature rsa = Signature.getInstance( "SHA1withRSA", pv );
		

		if ( sCer == null ){
			_strerr= LabelManager.get("ERR_RAW_NOCERT");
			return null;
		}
		
		if ( pk == null ){
			_strerr= LabelManager.get("ERR_RAW_NOKEY");
			return null;
		}
		
		rsa.initSign(pk);
		rsa.update(datos);

		byte[] res = rsa.sign();
		
		
		//Verification: 
		Signature rsa_vfy = Signature.getInstance( "SHA1withRSA");
		rsa_vfy.initVerify(sCer);
		rsa_vfy.initVerify(sCer.getPublicKey());
		rsa_vfy.update(datos);
		System.out.println("La verificación resultó:  " + rsa_vfy.verify(res));
		
		if ( res == null ){
			_strerr= LabelManager.get("ERROR_RAW_SIGNATURE");
		}
		
		return res;
	}
	
	public String getError(){
		return _strerr;
	}
}

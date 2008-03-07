package es.uji.dsign.crypto;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.MyCMSSignedDataGenerator;

import es.uji.dsign.util.i18n.LabelManager;


public class CMSSignatureFactory extends AbstractSignatureFactory implements ISignFormatProvider
{
    private Logger log = Logger.getLogger(CMSSignatureFactory.class);
    private String _strerr= "";
    
	public byte[] formatSignature(byte[] content, X509Certificate sCer, PrivateKey pk, Provider pv) throws KeyStoreException, Exception
	{
		// Init the provider registry
		super.initProviderList();
		
		MyCMSSignedDataGenerator gen = new MyCMSSignedDataGenerator();
		
		if ( sCer == null ){
			_strerr= LabelManager.get("ERROR_CMS_NOCERT");
			return null;
		}
				
		if ( pk == null ){
			_strerr= LabelManager.get("ERROR_CMS_NOKEY");
			return null;
		}
		
		gen.addSigner(pk, (X509Certificate) sCer, CMSSignedGenerator.DIGEST_SHA1);
		CMSProcessableByteArray cba = new CMSProcessableByteArray(content);

		List<Certificate> certList = new ArrayList<Certificate>();
		
		//TODO:  Add the intermediate CAs if we have them
		certList.add(sCer);
		
		CertStore certst = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
	
		gen.addCertificatesAndCRLs(certst);
			
		CMSSignedData data = gen.generate(cba, pv.getName());
		
		if (data != null)
		{
			return data.getEncoded();
		}
		else
		{
			_strerr= LabelManager.get("ERROR_CMS_SIGNATURE");
			return null;
		}
	}
	
	public String getError(){
		return _strerr;
	}
}

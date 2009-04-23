package es.uji.dsign.crypto.test.keystore;

import java.io.File;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.dsign.crypto.keystore.IKeyStoreHelper;
import es.uji.dsign.crypto.keystore.MozillaKeyStore;
import es.uji.dsign.crypto.keystore.PKCS11KeyStore;
import es.uji.dsign.crypto.mozilla.Mozilla;

public class MozillaKeyStoreTest
{
	public static void main(String[] args)
	{

		try{
			MozillaKeyStore mks2 = new MozillaKeyStore(); 
		//TODO: AQUI ESTA EL PROBLEMA !!! 
			mks2.load("".toCharArray());
			mks2.cleanUp();
			
		}
		catch (Exception e){
			e.printStackTrace();
		}
		
		if (Security.getProvider("BC") == null)
		{
			BouncyCastleProvider bcp = new BouncyCastleProvider();
			Security.addProvider(bcp);
		}

		IKeyStoreHelper mks = null;
				
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

		try
		{
			Mozilla mozilla= new Mozilla();
								
			mks = (IKeyStoreHelper) new PKCS11KeyStore(mozilla.getPkcs11ConfigInputStream(),
					mozilla.getPkcs11FilePath(), 
					mozilla.getPkcs11InitArgsString());
									
			mks.load(null);
			
			mks = (IKeyStoreHelper) new MozillaKeyStore();
			mks.load("pruebacert".toCharArray());
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		try
		{
			byte[] b = "hola que tal".getBytes();
			
			/*
			 * byte[] b= new byte[1000];
			 * 
			 * File fd= new File("/dev/urandom");
			 * 
			 * FileInputStream fin = new FileInputStream(fd); fin.read(b, 0,
			 * 1000); fin.close();
			 */

			System.out.println("\nCertificados en el store de mozilla:");
			
			for (Enumeration e = mks.aliases(); e.hasMoreElements();)
			{
				String str = (String) e.nextElement();
				Certificate cer = mks.getCertificate("FIRMA");
				PrivateKey k = (PrivateKey) mks.getKey("FIRMA");
				//MSCAPIPrivateKey k2 = new MSCAPIPrivateKey(str);
				// PublicKey k2= (PublicKey)cer.getPublicKey();
				System.out.println("SubjectDN: " + ((X509Certificate) cer).getSubjectDN());
				System.out.println("IssuerDN: " + ((X509Certificate) cer).getIssuerDN());
				String IssuerDN = ((X509Certificate) cer).getIssuerDN().getName();
				IssuerDN = IssuerDN.substring(IssuerDN.indexOf("O="));
				IssuerDN = IssuerDN.replaceFirst("O=", "");
				
				if (IssuerDN.indexOf("=") > -1)
				{
					IssuerDN = IssuerDN.substring(0, IssuerDN.indexOf("=") - 3);
				}

				IssuerDN = IssuerDN.replace('\"', ' ');
				IssuerDN = IssuerDN.trim();

				System.out.println("O= " + IssuerDN);

				System.out.println("========KEY===========: " + k);
				//System.out.println("========KEY2===========: " + k2);

				System.out.println("Certificado= " + cer.toString());
				System.out.println("\n");
				System.out.println("\nFIRMA: ");
				// byte[] b= {'j','a','r','r','l'};

				byte[] rs = mks.signMessage(b, str);

				gen.addSigner(k, (X509Certificate) cer, CMSSignedGenerator.DIGEST_SHA1);

				// gen.addCertificatesAndCRLs(cer);
				CMSProcessableByteArray cba = new CMSProcessableByteArray(b);

				List<Certificate> certList = new ArrayList<Certificate>();
				certList.add(cer);
				CertStore certst = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");

				gen.addCertificatesAndCRLs(certst);
				CMSSignedData data = gen.generate(cba, mks.getProvider().getName());

				File f2 = new File("caca.p7");
				FileOutputStream fos2 = new FileOutputStream(f2);
				fos2.write(data.getEncoded(), 0, data.getEncoded().length);
				fos2.close();

				System.out.println(data.getEncoded().length);

				CMSSignedData s = data;
				// Verification
				CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");
				SignerInformationStore signers = s.getSignerInfos();
				Collection c = signers.getSigners();
				Iterator it = c.iterator();

				while (it.hasNext())
				{
					SignerInformation signer = (SignerInformation) it.next();
					Collection certCollection = certs.getCertificates(signer.getSID());

					Iterator certIt = certCollection.iterator();
					X509Certificate cert = (X509Certificate) certIt.next();

					if (signer.verify(cert.getPublicKey(), "BC"))
					{
						System.out.println("Verificado");
					}
				}

				// End of verification

				System.out.println("Longitud: " + rs.length);
				// System.out.println("\n\n\nFIRMA FIRMA FIRMA \n" + new
				// String(b64.encode(rs)));
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		mks.cleanUp();
	}
}
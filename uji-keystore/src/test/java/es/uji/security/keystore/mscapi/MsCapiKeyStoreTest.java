package es.uji.security.keystore.mscapi;

//package es.uji.security.keystore.mscapi;
//
//import java.security.PrivateKey;
//import java.security.Security;
//import java.security.cert.CertStore;
//import java.security.cert.Certificate;
//import java.security.cert.CollectionCertStoreParameters;
//import java.security.cert.X509Certificate;
//import java.util.ArrayList;
//import java.util.Collection;
//import java.util.Enumeration;
//import java.util.Iterator;
//import java.util.List;
//
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//
//import es.uji.security.keystore.IKeyStoreHelper;
//import es.uji.security.keystore.mscapi.MSCAPIProvider;
//import es.uji.security.keystore.mscapi.MsCapiKeyStore;
//
//public class MsCapiKeyStoreTest
//{
//	public static void main(String[] args)
//	{
//		if (Security.getProvider("BC") == null)
//		{
//			BouncyCastleProvider bcp = new BouncyCastleProvider();
//			Security.addProvider(bcp);
//		}
//
//		if (Security.getProvider("UJI-MSCAPI") == null)
//		{
//			MSCAPIProvider uji = new MSCAPIProvider();
//			Security.addProvider(uji);
//		}
//
//		System.loadLibrary("MicrosoftCryptoApi_0_3");
//		
//		IKeyStoreHelper mks = null;
//		
//		try
//		{
//			mks = (IKeyStoreHelper) new MsCapiKeyStore();
//			mks.load("".toCharArray());
//			for (Enumeration e= mks.aliases(); e.hasMoreElements();)
//				System.out.println("Encontrado cert antes : " + e.nextElement());
//		}
//		catch (Exception e)
//		{
//			e.printStackTrace();
//		}
//
//		try
//		{
//			byte[] b = "hola que tal estamos colega".getBytes();
//			
//			/*
//			 * byte[] b= new byte[1000];
//			 * 
//			 * File fd= new File("/dev/urandom");
//			 * 
//			 * FileInputStream fin = new FileInputStream(fd); fin.read(b, 0,
//			 * 1000); fin.close();
//			 */
//
//			// System.out.println("\nCertificados en el store MY de MSCAPI:");
//			for (Enumeration e = mks.aliases(); e.hasMoreElements();)
//			{
//				mks.cleanUp();
//				
//				try
//				{
//					mks = (IKeyStoreHelper) new MsCapiKeyStore();
//					mks.load("".toCharArray());
//					for (Enumeration en2= mks.aliases(); en2.hasMoreElements();)
//						System.out.println("Encontrado cert antes : " + en2.nextElement());
//				}
//				catch (Exception ex)
//				{
//					ex.printStackTrace();
//				}
//				
//				
//				String str = (String) e.nextElement();
//				Certificate cer = mks.getCertificate(str);
//				PrivateKey k = (PrivateKey) mks.getKey(str);
//
//				// PublicKey k2= (PublicKey)cer.getPublicKey();
//
//				// System.out.println("========KEY===========: " + k);
//
//				// System.out.println("Certificado= " + cer.toString());
//				// System.out.println("\n");
//				System.out.println("\nFIRMA: ");
//				// byte[] b= {'j','a','r','r','l'};
//
//				//byte[] rs = mks.signMessage(b, str);
//				//gen.setHash(rs);
//				MyCMSSignedDataGenerator gen = new MyCMSSignedDataGenerator();
//				gen.addSigner(k, (X509Certificate) cer, CMSSignedGenerator.DIGEST_SHA1);
//
//				// gen.addCertificatesAndCRLs(cer);
//				CMSProcessableByteArray cba = new CMSProcessableByteArray(b);
//
//				List<Certificate> certList = new ArrayList<Certificate>();
//				certList.add(cer);
//				CertStore certst = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
//
//				gen.addCertificatesAndCRLs(certst);
//				CMSSignedData data = gen.generate(cba, mks.getProvider().getName());
//
//				/*
//		 		  File f2 = new File("caca.p7");
//				  FileOutputStream fos2 = new FileOutputStream(f2);
//				  fos2.write(data.getEncoded(), 0, data.getEncoded().length);
//				  fos2.close();
//
//				  System.out.println(data.getEncoded().length);
//				  File f = new File("caca2");
//			 	  FileOutputStream fos = new FileOutputStream(f);
//				  fos.write(data.getEncoded());
//				  fos.close();
//			 	*/
//				
//				CMSSignedData s = data;
//				// Verification
//				CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");
//				SignerInformationStore signers = s.getSignerInfos();
//				Collection c = signers.getSigners();
//				Iterator it = c.iterator();
//
//				while (it.hasNext())
//				{
//					SignerInformation signer = (SignerInformation) it.next();
//					Collection certCollection = certs.getCertificates(signer.getSID());
//
//					Iterator certIt = certCollection.iterator();
//					X509Certificate cert = (X509Certificate) certIt.next();
//
//					if (signer.verify(cert.getPublicKey(), "BC"))
//					{
//						System.out.println("Verificado");
//					}
//					else
//					{
//						System.out.println("Fallo en la Verfificacion");
//					}
//				}
//				
//				for (Enumeration enu= mks.aliases(); enu.hasMoreElements();)
//					System.out.println("Encontrado cert antes durante: " + enu.nextElement());
//				
//				// End of verification
//
//				// System.out.println("Longitud: " + rs.length);
//				// System.out.println("\n\n\nFIRMA FIRMA FIRMA \n" + new
//				// String(b64.encode(rs)));
//			}
//		}
//		catch (Exception e)
//		{
//			e.printStackTrace();
//		}
//		
//		try{
//		for (Enumeration en= mks.aliases(); en.hasMoreElements();)
//			System.out.println("Encontrado cert despues : " + en.nextElement());
//		}
//		catch(Exception e)
//		{
//			
//		}
//		mks.cleanUp();
//	}
// }

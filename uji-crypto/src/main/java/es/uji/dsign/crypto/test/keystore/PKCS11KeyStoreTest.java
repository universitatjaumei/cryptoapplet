//package es.uji.dsign.crypto.test.keystore;
//
//import es.uji.dsign.crypto.keystore.PKCS11KeyStore;
//import es.uji.dsign.crypto.mozilla.Mozilla;
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
//import java.io.ByteArrayInputStream;
//import java.io.File;
//import java.io.FileOutputStream;
//
//import org.bouncycastle.cms.CMSProcessableByteArray;
//import org.bouncycastle.cms.CMSSignedData;
//import org.bouncycastle.cms.CMSSignedGenerator;
//import org.bouncycastle.cms.SignerInformation;
//import org.bouncycastle.cms.SignerInformationStore;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//
//public class PKCS11KeyStoreTest {
//
//	public static void main(String[] args) {
//
//		
//		
//		if (Security.getProvider("BC") == null)
//		{
//			BouncyCastleProvider bcp = new BouncyCastleProvider();
//			Security.addProvider(bcp);
//		}
//
//
//		//String cfgDir=  _mozilla.getCurrentProfiledir().replace("\\", "/").replace(" ", "\\ ");
//		String config= "name = Clauer\n" + 
//		"library = /usr/local/lib/libclauerpkcs11.so\n" +  
//		"attributes= compatibility\n" +  
//		"slot=1\n";
//		//"nssArgs=\"configdir='" + cfgDir + "' certPrefix='' keyPrefix='' secmod=' secmod.db' flags=readOnly\n";
//
//		ByteArrayInputStream bais= new ByteArrayInputStream(config.getBytes());
//
//		String lib= "/usr/local/lib/libclauerpkcs11.so.0.0.0";
//
//		//ClauerKeyStore p11ks=null;
//		PKCS11KeyStore p11ks=null;
//
//		try{
//			System.out.println("Trying against Clauer Pkcs#11");
//			p11ks= new PKCS11KeyStore(bais, lib, null);
//			System.out.println("instantiation passed");
//			//p11ks.load(null);
//			p11ks.load("123clauer".toCharArray());
//			/*for (Certificate c: p11ks.getUserCertificates()){
//				System.out.println("  Got Certificate with DN: " + ((X509Certificate)c).getSubjectDN());
//				System.out.println("With Alias: " + p11ks.getAliasFromCertificate(c));
//			}*/
//			
//			//p11ks= new ClauerKeyStore();
//			//p11ks.load("123clauer".toCharArray());
//			
//			
//			/*for (Certificate c: p11ks.getUserCertificates()){
//				System.out.println("  Got Certificate with DN: " + ((X509Certificate)c).getSubjectDN());
//				System.out.println("With Alias: " + p11ks.getAliasFromCertificate(c));
//			}*/
//			
//		}
//		catch (Exception e){
//			e.printStackTrace();
//		}
//		System.out.println("\n");
//
//
//		//Vamos a firmar: 
//
//		byte[] b = "hola que tal".getBytes();
//		MyCMSSignedDataGenerator gen = new MyCMSSignedDataGenerator();
//		try{		
//			for (Enumeration e = p11ks.aliases(); e.hasMoreElements();)
//			{
//				String str = (String) e.nextElement();
//				Certificate cer = p11ks.getCertificate(str);
//				PrivateKey k = (PrivateKey) p11ks.getKey(str);
//				System.out.println("SubjectDN: " + ((X509Certificate) cer).getSubjectDN());
//				System.out.println("IssuerDN: " + ((X509Certificate) cer).getIssuerDN());
//				String IssuerDN = ((X509Certificate) cer).getIssuerDN().getName();
//				IssuerDN = IssuerDN.substring(IssuerDN.indexOf("O="));
//				IssuerDN = IssuerDN.replaceFirst("O=", "");
//
//				if (IssuerDN.indexOf("=") > -1)
//				{
//					IssuerDN = IssuerDN.substring(0, IssuerDN.indexOf("=") - 3);
//				}
//
//				IssuerDN = IssuerDN.replace('\"', ' ');
//				IssuerDN = IssuerDN.trim();
//
//				System.out.println("O= " + IssuerDN);
//
//				System.out.println("========KEY===========: " + k);
//				//System.out.println("========KEY2===========: " + k2);
//
//				System.out.println("Certificado= " + cer.toString());
//				System.out.println("\n");
//				System.out.println("\nFIRMA: ");
//				// byte[] b= {'j','a','r','r','l'};
//
//				//byte[] rs = p11ks.signMessage(b, str);
//
//				gen.addSigner(k, (X509Certificate) cer, CMSSignedGenerator.DIGEST_SHA1);
//				byte[] b2= new byte[] {0x73,0x1b,(byte)0xd7,(byte)0xd6,(byte)0xd5,0x30,0x29,(byte)0x84,0x67,(byte)0xc7,0x64,(byte)0x8d,(byte)0x89,0x39,0x12,(byte)0x8e,0x33,(byte)0xa2,(byte)0xb3,(byte)0x9d};
//				gen.setHash(b2);
//				
//				CMSProcessableByteArray cba = new CMSProcessableByteArray(b);
//
//				List<Certificate> certList = new ArrayList<Certificate>();
//				certList.add(cer);
//				CertStore certst = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
//
//				gen.addCertificatesAndCRLs(certst);
//				CMSSignedData data = gen.generate(cba, p11ks.getProvider().getName());
//
//				File f2 = new File("caca.p7");
//				FileOutputStream fos2 = new FileOutputStream(f2);
//				fos2.write(data.getEncoded(), 0, data.getEncoded().length);
//				fos2.close();
//
//				System.out.println(data.getEncoded().length);
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
//				}
//
//				// End of verification
//
//				//System.out.println("Longitud: " + rs.length);
//				// System.out.println("\n\n\nFIRMA FIRMA FIRMA \n" + new
//				// String(b64.encode(rs)));
//			}
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//		bais= new ByteArrayInputStream(config.getBytes());
//
//		//String lib= "/usr/lib/libsoftokn3.so";
//		Mozilla _mozilla= new Mozilla();
//		try{
//			System.out.println("Trying against Mozilla NSS softkn library");
//
//
//			PKCS11KeyStore p11ks2= new PKCS11KeyStore(_mozilla.getPkcs11ConfigInputStream(), "/usr/lib/libsoftokn3.so", _mozilla.getPkcs11InitArgsString());
//
//			p11ks2.load(null);
//
//			for (Certificate c: p11ks2.getUserCertificates()){
//				System.out.println("  Got Certificate with DN: " + ((X509Certificate)c).getSubjectDN());
//				System.out.println("With Alias: " + p11ks.getAliasFromCertificate(c));
//			}
//			p11ks2.load("pruebacert".toCharArray());
//		}
//		catch (Exception e){
//			e.printStackTrace();
//		}
//		System.out.println("\n");
//	}
//}

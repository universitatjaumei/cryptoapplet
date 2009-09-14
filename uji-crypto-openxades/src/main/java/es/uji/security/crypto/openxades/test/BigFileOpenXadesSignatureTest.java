package es.uji.security.crypto.openxades.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.openxades.ConfigHandler;
import es.uji.security.crypto.openxades.digidoc.CertValue;
import es.uji.security.crypto.openxades.digidoc.DataFile;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.TimestampInfo;
import es.uji.security.crypto.openxades.digidoc.factory.CanonicalizationFactory;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.timestamp.TSResponse;
import es.uji.security.crypto.timestamp.TSResponseToken;
import es.uji.security.crypto.timestamp.TimeStampFactory;

public class BigFileOpenXadesSignatureTest {


	public void writebyteFile(int mb, String where) throws Exception{


		File f= new File(where);
		f.delete();

		FileOutputStream fos= new FileOutputStream(f);

		byte[] junk= new byte[1024 * 1024];

		for (int i=0; i<mb; i++){
			fos.write(junk);
		} 
		fos.close();
	}

	public void signAndVerify(String file, String pwd) throws Exception
	{
        ConfigManager conf = ConfigManager.getInstance();
        
		CertValue cval= null;

		BouncyCastleProvider bcp = new BouncyCastleProvider();
		Security.addProvider(bcp);
	
		// Cargando certificado de aplicación
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream("/home/paul/tmp/mio.p12"), pwd.toCharArray());

		// Recuperando clave privada para firmar
		Certificate certificate = keystore.getCertificate(keystore.aliases().nextElement());
		Key key = keystore.getKey(keystore.aliases().nextElement(), pwd.toCharArray());

		// Firmando documento
		SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
		DataFile df = sdoc.addDataFile(new File(file), "application/binary", DataFile.CONTENT_EMBEDDED_BASE64);

		Signature sig = sdoc.prepareSignature((X509Certificate) certificate, new String[] { "a Role" },null);

		// Do the signature      
		byte[] sidigest = sig.getSignedContent();
		if (sidigest == null)
		{
			System.err.println("Error getting signedcontent for digest.");
			System.exit(-1);
		}

		java.security.Signature rsa = java.security.Signature.getInstance("SHA1withRSA");
		rsa.initSign((PrivateKey)key);
		rsa.update(sidigest);
		byte[] res = rsa.sign();

		if (res == null)
		{
			System.err.println("Error signing the hash.");
			System.exit(-1);
		}

		// Add the signature to the signed doc
		sig.setSignatureValue(res);

		int tsaCount = conf.getIntProperty("DIGIDOC_TSA_COUNT", 0);
		if (tsaCount != 0)
		{
			String tsaUrl = conf.getProperty("DIGIDOC_TSA1_URL");
			byte[] signatureValue = sig.getSignatureValue().toString().getBytes();

			TSResponse response = TimeStampFactory.getTimeStampResponse(tsaUrl, signatureValue,
					true);

			TSResponseToken responseToken= new TSResponseToken(response);

			TimestampInfo ts = new TimestampInfo("TS1", TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
			ts.setTimeStampResponse(response);
			ts.setSignature(sig);
			ts.setHash(responseToken.getMessageImprint());

			sig.addTimestampInfo(ts);

			String tsa1_ca = conf.getProperty("DIGIDOC_TSA1_CA_CERT");

			X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);

			cval = new CertValue();
			cval.setType(CertValue.CERTVAL_TYPE_TSA);
			cval.setCert(xcaCert);
			cval.setId(sig.getId() + "-TSA_CERT");

			// Check the certificate validity against the timestamp:
			Date d = ts.getTime();
		}
		
		if (tsaCount != 0)
		{
			sig.addCertValue(cval);
		}

		if (conf.getProperty("DIGIDOC_CERT_VERIFIER").trim().equals("OCSP"))
		{
			sig.getConfirmation();
		}

		String tsaUrl = conf.getProperty("DIGIDOC_TSA1_URL");

		byte[] completeCertificateRefs = sig.getUnsignedProperties()
		.getCompleteCertificateRefs().toXML();

		byte[] completeRevocationRefs = sig.getUnsignedProperties().getCompleteRevocationRefs()
		.toXML();

		CanonicalizationFactory canFac = ConfigHandler.getCanonicalizationFactory();
		
		byte[] canCompleteCertificateRefs = canFac.canonicalize(completeCertificateRefs,
			   SignedDoc.CANONICALIZATION_METHOD_20010315);

		byte[] canCompleteRevocationRefs = canFac.canonicalize(completeRevocationRefs,
			   SignedDoc.CANONICALIZATION_METHOD_20010315);


		byte[] refsOnlyData = new byte[canCompleteCertificateRefs.length
		                               + canCompleteRevocationRefs.length];
		System.arraycopy(canCompleteCertificateRefs, 0, refsOnlyData, 0,
				canCompleteCertificateRefs.length);
		System.arraycopy(canCompleteRevocationRefs, 0, refsOnlyData,
				canCompleteCertificateRefs.length, canCompleteRevocationRefs.length);

		TSResponse response = TimeStampFactory.getTimeStampResponse(tsaUrl, refsOnlyData, true);
		TSResponseToken responseToken= new TSResponseToken(response);

		TimestampInfo ts = new TimestampInfo("TS2", TimestampInfo.TIMESTAMP_TYPE_REFS_ONLY);
		ts.setTimeStampResponse(response);
		ts.setSignature(sig);
		ts.setHash(responseToken.getMessageImprint());

		sig.addTimestampInfo(ts);

		sdoc.writeToFile(new File("/tmp/signed-output.xml"));

		DigiDocFactory digFac = ConfigHandler.getDigiDocFactory();
		SignedDoc r_sdoc = digFac.readSignedDoc(new FileInputStream("/tmp/signed-output.xml"));

		boolean confirmation = conf.getProperty(
		"DIGIDOC_DEMAND_OCSP_CONFIRMATION_ON_VERIFY").equals("true");

		ArrayList<String> allErrors = new ArrayList<String>();

		for (int i = 0; i < r_sdoc.countSignatures(); i++)
		{
			Signature r_sig = r_sdoc.getSignature(i);
			ArrayList errs = r_sig.verify(r_sdoc, false, confirmation);

			if (errs.size() > 0)
			{
				for (int j = 0; j < errs.size(); j++)
				{
					allErrors.add(((DigiDocException) errs.get(j)).getMessage());
				}
			}
		}

		if (allErrors.size() == 0)
		{
			System.out.println("Ok");
		}
		else
		{
			for (String e : allErrors)
			{
				System.out.println(e);
			}
		}
	}

	public static void main(String[] args) throws Exception
	{
		String pwd = args[0];
		String file= "/tmp/file";
		Logger.getRootLogger().setLevel(Level.OFF);
		BigFileOpenXadesSignatureTest bfst= new BigFileOpenXadesSignatureTest();

		for (int i=10; i<100; i+=10){
			System.out.println("\n\nTrying with "+ i + " MB ");
			Thread.currentThread().sleep(1000);
			bfst.writebyteFile(i, file + i);
			bfst.signAndVerify(file + i, pwd);
		}
	}
}

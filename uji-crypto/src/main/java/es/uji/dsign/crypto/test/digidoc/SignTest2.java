package es.uji.dsign.crypto.test.digidoc;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import es.uji.dsign.crypto.SHA1Digest;
import es.uji.dsign.crypto.XAdESSignatureFactory;
import es.uji.dsign.crypto.digidoc.CertValue;
import es.uji.dsign.crypto.digidoc.DataFile;
import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.Signature;
import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.TimestampInfo;
import es.uji.dsign.crypto.digidoc.factory.DigiDocFactory;
import es.uji.dsign.crypto.digidoc.utils.ConfigManager;
import es.uji.dsign.crypto.digidoc.utils.ConvertUtils;
import es.uji.dsign.crypto.keystore.*;

public class SignTest2 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try{
			XAdESSignatureFactory XFact= new XAdESSignatureFactory();

			MozillaKeyStore mks = new MozillaKeyStore();
			mks.load("123clauer".toCharArray());
		
			Enumeration en= mks.aliases();
			String alias= (String) en.nextElement();

			//XFact.formatSignature(mks, alias, "Hola como lo llevamos".getBytes(), null);

			//log.debug("Using XAdESSignatureFactory");
			//log.debug(ksh.getProvider().getName() + " provider found");

			// Leemos el fichero de configuracion
			ConfigManager.init("/tmp/jdigidoc.cfg");
			//log.debug("JDigidoc configuration file loaded");

			// Creamos un nuevo SignedDoc XAdES
			SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);

			// Añadimos una nueva referencia de fichero en base64 ... aunque establecemos el body 
			DataFile df = sdoc.addDataFile(new File("/tmp/f"), "application/binary", DataFile.CONTENT_DETATCHED /*.CONTENT_EMBEDDED_BASE64*/);		
			//df.setBody(ConvertUtils.str2data("hola como estamos"), "UTF8");

			Certificate cert = null;


			cert = mks.getCertificate(alias);

			//log.debug("Got certificate: " + cert);
			//log.debug("Certificat alias: " + alias);

			PrivateKey privKey = (PrivateKey) mks.getKey(alias);

			// Preparamos la firma
			//TODO: Soporte para roles dentro de la firma
			Signature sig = sdoc.prepareSignature((X509Certificate) cert, new String[] { "PDI" }, null);

			// Firmamos
			System.out.println("\n\n\nSignedContent: " + new String(sig.getSignedContent()) + "\n\n\n");
			byte[] sidigest= sig.getSignedContent();
			java.security.Signature rsa = java.security.Signature.getInstance("SHA1withRSA", mks.getProvider());
			rsa.initSign(privKey);
			rsa.update(sidigest);
			byte[] res = rsa.sign();

			// log.debug("Signing XAdES info. XAdES signature length " + res.length);

			// Añadimos la firma al SignedDoc
			sig.setSignatureValue(res);

			// Verificación OCSP
			// sig.getConfirmation();

			/*
			// Obtenemos el timestamp y lo añadimos 
			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			// Request TSA to return certificate
			reqGen.setCertReq(false);

			SHA1Digest sha = new SHA1Digest();
			sha.engineUpdate(sig.getSignatureValue().toString().getBytes(),0,
					sig.getSignatureValue().toString().length());

			byte[] hash = sha.engineDigest();

			TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, hash);
			byte[] enc_req = request.getEncoded();

			String tsaUrl= ConfigManager.instance().getProperty("DIGIDOC_TSA1_URL");
			URL url = new URL(tsaUrl);

			URLConnection urlConn = url.openConnection();
			urlConn.setDoInput(true);
			urlConn.setDoOutput(true);
			urlConn.setUseCaches(false);

			urlConn.setRequestProperty("Content-Type", "application/timestamp-query");
			urlConn.setRequestProperty("Content-Length", "" + enc_req.length);

			OutputStream printout = urlConn.getOutputStream();
			printout.write(enc_req);
			printout.flush();
			printout.close();

			InputStream in = urlConn.getInputStream();				


			TimeStampResponse resp = new TimeStampResponse(in);

			resp.validate(request);

			//log.debug("Timestamp validated");

			TimestampInfo ts = new TimestampInfo("TS1", TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
			ts.setTimeStampResponse(resp);		
			ts.setSignature(sig);
			ts.setHash(resp.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest());

			sig.addTimestampInfo(ts);

			String tsa1_ca= ConfigManager.instance().getProperty("DIGIDOC_TSA1_CA_CERT");		
			X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);

			CertValue cval = new CertValue();
			cval.setType(CertValue.CERTVAL_TYPE_TSA);
			cval.setCert(xcaCert);
			cval.setId(sig.getId() + "-TSA_CERT");
			*/

			System.out.println("SIGNED DOC: " + sdoc.toXML());
			sdoc.writeToFile(new File("/tmp/sig.xml"));

			
			//log.debug("OSCP: Verify certificates");

			//TODO: Eliminar, solo desarrollo
			/*{
				String xadesFile = System.getProperty("user.home") + System.getProperty("file.separator") + "data.ddoc";			
				sdoc.writeToFile(new File(xadesFile));

				// Verificamos el documento creado
				DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
				sdoc = digFac.readSignedDoc(xadesFile);        

				for (int i=0 ; i<sdoc.countSignatures() ; i++) 
				{
					sig = sdoc.getSignature(i);
					//log.debug("Signature: " + sig.getId() + " - " +
					//		  sig.getKeyInfo().getSubjectLastName() + "," +
					//		  sig.getKeyInfo().getSubjectFirstName() + "," +
					//		  sig.getKeyInfo().getSubjectPersonalCode());

					//log.debug("SigInfo: " + sig.getSignedInfo().toString());
					 
					ArrayList errs = sig.verify(sdoc, false, false);

					if(errs.size() == 0)
					{
						System.out.println("XAdES document is correct!!!");
					}
					else
					{        	
						for (int j=0 ; j<errs.size() ; j++)
						{
							System.out.println("JDigidoc Error: " + (DigiDocException) errs.get(i));
						}
					}
				}
			}*/
			
	}catch (Exception e){
		e.printStackTrace();
	}	
}
}

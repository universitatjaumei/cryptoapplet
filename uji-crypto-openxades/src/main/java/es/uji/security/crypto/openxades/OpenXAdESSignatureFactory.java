package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.openxades.digidoc.CertValue;
import es.uji.security.crypto.openxades.digidoc.DataFile;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.TimestampInfo;
import es.uji.security.crypto.openxades.digidoc.factory.CanonicalizationFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;
import es.uji.security.crypto.timestamp.TSResponse;
import es.uji.security.crypto.timestamp.TSResponseToken;
import es.uji.security.crypto.timestamp.TimeStampFactory;
import es.uji.security.util.ConfigHandler;
import es.uji.security.util.OS;
import es.uji.security.util.i18n.LabelManager;

public class OpenXAdESSignatureFactory implements ISignFormatProvider
{
	private Logger log = Logger.getLogger(OpenXAdESSignatureFactory.class);

	private String _strerr = "";
	private String signerRole = "UNSET";
	private String xadesFileName = "data.xml";
	private String xadesFileMimeType = "application/binary";

	public void setSignerRole(String srole)
	{
		signerRole = srole;
	}

	public void setXadesFileName(String filename)
	{
		xadesFileName = filename;
	}

	public void setXadesFileMimeType(String fmimetype)
	{
		xadesFileMimeType = fmimetype;
	}

	public InputStream formatSignature(SignatureOptions sigOpt) throws Exception
	{
		/*
		 * for ( Enumeration enu= ksh.aliases(); enu.hasMoreElements(); ){
		 * System.out.println("Next elem: " + enu.nextElement()); }
		 */
		//Logger.getRootLogger().setLevel(Level.OFF);	

		String file= "jar://data.xml";
		X509Certificate sCer = sigOpt.getCertificate();
		PrivateKey pk = sigOpt.getPrivateKey();
		Provider pv = sigOpt.getProvider();
		byte[] toSign= null;
		File random= new File(OS.getSystemTmpDir() + "/signatureData.dat"); 

		log.debug("Using XAdESSignatureFactory");
		log.debug(pv.getName() + " provider found");

		Properties prop = ConfigHandler.getProperties();
		if (prop != null)
		{
			ConfigManager.init(prop);
		}
		else
		{
			_strerr = LabelManager.get("ERROR_DDOC_NOCONFIGFILE");
			return null;
		}

		// Here we must to guess whether tmp file is necessary or not.
		if (sigOpt.getSwapToFile()){
			OS.dumpToFile(random ,  sigOpt.getToSignInputStream());
		}

		// Creamos un nuevo SignedDoc XAdES
		SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
		// A�adimos una nueva referencia de fichero en base64 ... aunque establecemos el body
		DataFile df = sdoc.addDataFile(new File(file), "application/binary",
				DataFile.CONTENT_EMBEDDED_BASE64);

		System.out.println("Seleccionando nombre fichero a: " + xadesFileName);
		sdoc.getDataFile(0).setFileName(xadesFileName);
		sdoc.getDataFile(0).setMimeType(xadesFileMimeType);

		if (!sigOpt.getSwapToFile()){
			toSign = OS.inputStreamToByteArray(sigOpt.getToSignInputStream());	
			df.setBody(toSign);
			df.setSize(toSign.length);
		}

		InputStream res = signDoc(sdoc, sigOpt);

		random.delete();

		return res;
	}

	protected InputStream signDoc(SignedDoc sdoc, SignatureOptions sigOpt) throws Exception
	{

		X509Certificate sCer = sigOpt.getCertificate();
		PrivateKey pk = sigOpt.getPrivateKey();
		Provider pv = sigOpt.getProvider();
		File random= new File(OS.getSystemTmpDir() + "/signature.xsig");

		if (sCer == null)
		{
			_strerr = LabelManager.get("ERROR_DDOC_NOCERT");
			return null;
		}

		if (pk == null)
		{
			_strerr = LabelManager.get("ERROR_DDOC_NOKEY");
			return null;
		}

		// Prepare the signature
		// TODO: Role support in the signature
		Signature sig = sdoc.prepareSignature((X509Certificate) sCer, new String[] { signerRole },
				null);
		CertValue cval = null;

		// Do the signature
		byte[] sidigest = sig.getSignedContent();
		if (sidigest == null)
		{
			_strerr = LabelManager.get("ERROR_DDOC_NODIGEST");
			return null;
		}

		java.security.Signature rsa = java.security.Signature.getInstance("SHA1withRSA", pv);
		rsa.initSign(pk);
		rsa.update(sidigest);
		byte[] res = rsa.sign();

		if (res == null)
		{
			log.error("No se pudo calcular la firma");
			_strerr = LabelManager.get("ERROR_DDOC_SIGNATURE");
			return null;
		}

		log.debug("Signing XAdES info. XAdES signature length " + res.length);

		// Add the signature to the signed doc
		sig.setSignatureValue(res);

		// Get the timestamp and add it

		int tsaCount = ConfigManager.instance().getIntProperty("DIGIDOC_TSA_COUNT", 0);
		if (tsaCount != 0)
		{
			String tsaUrl = ConfigManager.instance().getProperty("DIGIDOC_TSA1_URL");
			byte[] signatureValue = sig.getSignatureValue().toString().getBytes();
			
			TSResponse response = TimeStampFactory.getTimeStampResponse(tsaUrl, signatureValue,
					true);

			TSResponseToken responseToken= new TSResponseToken(response);

			TimestampInfo ts = new TimestampInfo("TS1", TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
			ts.setTimeStampResponse(response);
			ts.setSignature(sig);
			ts.setHash(responseToken.getMessageImprint());

			sig.addTimestampInfo(ts);

			String tsa1_ca = ConfigManager.instance().getProperty("DIGIDOC_TSA1_CA_CERT");

			if (tsa1_ca == null)
			{
				_strerr = LabelManager.get("ERROR_DDOC_TSACA");
				return null;
			}

			X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);

			cval = new CertValue();
			cval.setType(CertValue.CERTVAL_TYPE_TSA);
			cval.setCert(xcaCert);
			cval.setId(sig.getId() + "-TSA_CERT");

			// Check the certificate validity against the timestamp:
			Date d = ts.getTime();

			try
			{
				sCer.checkValidity(d);
			}
			catch (CertificateException cex)
			{
				_strerr = LabelManager.get("ERROR_CERTIFICATE_EXPIRED");
				return null;
			}
		}

		try
		{
			// Añadimos certificado TSA
			if (tsaCount != 0)
			{
				sig.addCertValue(cval);
			}

			// Verificación OCSP
			if (ConfigManager.instance().getProperty("DIGIDOC_CERT_VERIFIER").trim().equals("OCSP"))
			{
				sig.getConfirmation();
			}

			String tsaUrl = ConfigManager.instance().getProperty("DIGIDOC_TSA1_URL");

			byte[] completeCertificateRefs = sig.getUnsignedProperties()
			.getCompleteCertificateRefs().toXML();

			byte[] completeRevocationRefs = sig.getUnsignedProperties().getCompleteRevocationRefs()
			.toXML();

			CanonicalizationFactory canFac = ConfigManager.instance().getCanonicalizationFactory();
			byte[] 	canCompleteCertificateRefs = canFac.canonicalize(completeCertificateRefs,
					SignedDoc.CANONICALIZATION_METHOD_20010315);

			byte[] 	canCompleteRevocationRefs = canFac.canonicalize(completeRevocationRefs,
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

			log.debug("Verificacion OCSP completa");

		}
		catch (DigiDocException e)
		{
			if (e.getCode() == DigiDocException.ERR_CERT_REVOKED)
			{
				_strerr = LabelManager.get("ERROR_DDOC_CERTREVOKED");
			}
			else if (e.getCode() == DigiDocException.ERR_CERT_EXPIRED)
			{
				_strerr = LabelManager.get("ERROR_DDOC_CERTEXPIRED");
			}
			else if (e.getCode() == DigiDocException.ERR_CA_CERT_READ)
			{
				_strerr = LabelManager.get("ERROR_DDOC_CERT_NOT_ALLOWED");
				// _strerr= LabelManager.get("ERROR_DDOC_CACERTREAD");
			}
			else if (e.getCode() == DigiDocException.ERR_OCSP_READ_FILE
					|| e.getCode() == DigiDocException.ERR_OCSP_ISSUER_CA_NOT_FOUND)
			{
				_strerr = LabelManager.get("ERROR_DDOC_CERT_NOT_ALLOWED");
			}
			else
			{
				_strerr = LabelManager.get("ERROR_DDOC_CERTGENERIC");
			}
			log.debug("\n\n" + this.getClass().getName()
					+ ": No se pudo realizar la confirmacion OCSP" + e.getMessage());
			// e.printStackTrace();
			return null;
		}

		// Return the signed and coded document
		// If the bigFile mode is set, we write the result ot a file and get back de 
		// FileInputStream 
		if (sigOpt.getSwapToFile()){
			sdoc.writeToFile(random);
			return new FileInputStream(random);
		}

		return new ByteArrayInputStream(sdoc.toXML().getBytes());
	}

	public String getError()
	{
		return _strerr;
	}
}

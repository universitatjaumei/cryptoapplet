package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
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

    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        String file = "jar://data.xml";

        Provider provider = signatureOptions.getProvider();
        

        log.debug("Using XAdESSignatureFactory");
        log.debug(provider.getName() + " provider found");

        Properties prop = ConfigHandler.getProperties();

        SignatureResult signatureResult = new SignatureResult();

        if (prop != null)
        {
            ConfigManager.init(prop);
        }
        else
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_DDOC_NOCONFIGFILE"));

            return signatureResult;
        }

        // Here we must to guess whether tmp file is necessary or not.
        
        File random = null;
        File ftoSign = new File("jar://data.xml");
        
        if (signatureOptions.getSwapToFile())
        {
            new File(OS.getSystemTmpDir() + "/signatureData.dat");
            OS.dumpToFile(random, signatureOptions.getDataToSign());
            xadesFileName= random.getAbsolutePath();
            ftoSign= random;
        }		

        // Creamos un nuevo SignedDoc XAdES
		SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
		// A�adimos una nueva referencia de fichero en base64 ... aunque establecemos el body
		DataFile df = sdoc.addDataFile(ftoSign, "application/binary",
				DataFile.CONTENT_EMBEDDED_BASE64);
        if (!signatureOptions.getSwapToFile())
        {
            byte[] data = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
            df.setBody(data);
            df.setSize(data.length);
        }
        
        sdoc.getDataFile(0).setFileName(xadesFileName);
        sdoc.getDataFile(0).setMimeType(xadesFileMimeType);

        signatureResult = signDoc(sdoc, signatureOptions);

        if (signatureOptions.getSwapToFile())
        {
        	try
        	{
        		random.delete();
        	}
        	catch (Exception e)
        	{
        		e.printStackTrace();
        	}
        }

        return signatureResult;
    }

    protected SignatureResult signDoc(SignedDoc signedDoc, SignatureOptions signatureOptions)
            throws Exception
    {
        X509Certificate certificate = signatureOptions.getCertificate();
        PrivateKey privateKey = signatureOptions.getPrivateKey();
        Provider provider = signatureOptions.getProvider();

        File random = new File(OS.getSystemTmpDir() + "/signature.xsig");

        SignatureResult signatureResult = new SignatureResult();

        if (certificate == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_DDOC_NOCERT"));

            return signatureResult;
        }

        if (privateKey == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_DDOC_NOKEY"));

            return signatureResult;
        }

        // Prepare the signature
        // TODO: Role support in the signature
        Signature signature = signedDoc.prepareSignature((X509Certificate) certificate,
                new String[] { signerRole }, null);
        CertValue certValue = null;

        // Do the signature
        byte[] sidigest = signature.getSignedContent();

        if (sidigest == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_DDOC_NODIGEST"));

            return signatureResult;
        }

        java.security.Signature rsa = java.security.Signature.getInstance("SHA1withRSA", provider);
        rsa.initSign(privateKey);
        rsa.update(sidigest);

        byte[] res = rsa.sign();

        if (res == null)
        {
            log.error("No se pudo calcular la firma");

            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_DDOC_SIGNATURE"));

            return signatureResult;
        }

        log.debug("Signing XAdES info. XAdES signature length " + res.length);

        // Add the signature to the signed doc
        signature.setSignatureValue(res);

        // Get the timestamp and add it
        int tsaCount = ConfigManager.instance().getIntProperty("DIGIDOC_TSA_COUNT", 0);

        if (tsaCount != 0)
        {
            String tsaUrl = ConfigManager.instance().getProperty("DIGIDOC_TSA1_URL");
            byte[] signatureValue = signature.getSignatureValue().toString().getBytes();

            TSResponse response = TimeStampFactory.getTimeStampResponse(tsaUrl, signatureValue,
                    true);

            TSResponseToken responseToken = new TSResponseToken(response);

            TimestampInfo ts = new TimestampInfo("TS1", TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
            ts.setTimeStampResponse(response);
            ts.setSignature(signature);
            ts.setHash(responseToken.getMessageImprint());

            signature.addTimestampInfo(ts);

            String tsa1_ca = ConfigManager.instance().getProperty("DIGIDOC_TSA1_CA_CERT");

            if (tsa1_ca == null)
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERROR_DDOC_TSACA"));

                return signatureResult;
            }

            X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);

            certValue = new CertValue();
            certValue.setType(CertValue.CERTVAL_TYPE_TSA);
            certValue.setCert(xcaCert);
            certValue.setId(signature.getId() + "-TSA_CERT");

            // Check the certificate validity against the timestamp:
            Date d = ts.getTime();

            try
            {
                certificate.checkValidity(d);
            }
            catch (CertificateException cex)
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERROR_CERTIFICATE_EXPIRED"));

                return signatureResult;
            }
        }

        try
        {
            // A�adimos certificado TSA
            if (tsaCount != 0)
            {
                signature.addCertValue(certValue);
            }

            // Verificación OCSP
            if (ConfigManager.instance().getProperty("DIGIDOC_CERT_VERIFIER").trim().equals("OCSP"))
            {
                signature.getConfirmation();
            }

            String tsaUrl = ConfigManager.instance().getProperty("DIGIDOC_TSA1_URL");

            byte[] completeCertificateRefs = signature.getUnsignedProperties()
                    .getCompleteCertificateRefs().toXML();

            byte[] completeRevocationRefs = signature.getUnsignedProperties()
                    .getCompleteRevocationRefs().toXML();

            CanonicalizationFactory canFac = ConfigManager.instance().getCanonicalizationFactory();
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
            TSResponseToken responseToken = new TSResponseToken(response);

            TimestampInfo ts = new TimestampInfo("TS2", TimestampInfo.TIMESTAMP_TYPE_REFS_ONLY);
            ts.setTimeStampResponse(response);
            ts.setSignature(signature);
            ts.setHash(responseToken.getMessageImprint());

            signature.addTimestampInfo(ts);

            log.debug("Verificacion OCSP completa");

        }
        catch (DigiDocException e)
        {
            log.debug("\n\n" + this.getClass().getName()
                    + ": No se pudo realizar la confirmacion OCSP" + e.getMessage());

            signatureResult.setValid(false);

            if (e.getCode() == DigiDocException.ERR_CERT_REVOKED)
            {
                signatureResult.addError(LabelManager.get("ERROR_DDOC_CERTREVOKED"));
            }
            else if (e.getCode() == DigiDocException.ERR_CERT_EXPIRED)
            {
                signatureResult.addError(LabelManager.get("ERROR_DDOC_CERTEXPIRED"));
            }
            else if (e.getCode() == DigiDocException.ERR_CA_CERT_READ)
            {
                signatureResult.addError(LabelManager.get("ERROR_DDOC_CERT_NOT_ALLOWED"));
            }
            else if (e.getCode() == DigiDocException.ERR_OCSP_READ_FILE
                    || e.getCode() == DigiDocException.ERR_OCSP_ISSUER_CA_NOT_FOUND)
            {
                signatureResult.addError(LabelManager.get("ERROR_DDOC_CERT_NOT_ALLOWED"));
            }
            else
            {
                signatureResult.addError(LabelManager.get("ERROR_DDOC_CERTGENERIC"));
            }

            return signatureResult;
        }

        // Return the signed and coded document
        // If the bigFile mode is set, we write the result ot a file and get back de
        // FileInputStream

        signatureResult.setValid(true);

        if (signatureOptions.getSwapToFile())
        {
            signedDoc.writeToFile(random);
            signatureResult.setSignatureData(new FileInputStream(random));
        }
        else
        {
            signatureResult.setSignatureData(new ByteArrayInputStream(signedDoc.toXML().getBytes()));
        }

        return signatureResult;
    }
}
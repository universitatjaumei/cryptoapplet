package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.ConfigManager;
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
import es.uji.security.util.Base64;
import es.uji.security.util.OS;
import es.uji.security.util.i18n.LabelManager;

public class OpenXAdESSignatureFactory implements ISignFormatProvider
{
    private Logger log = Logger.getLogger(OpenXAdESSignatureFactory.class);

    private String signerRole;
    private String xadesFileName = "data.xml";
    private String xadesFileMimeType = "application/binary";

    public void setSignerRole(String signerRole)
    {
        this.signerRole = signerRole;
    }

    public void setXadesFileName(String xadesFileName)
    {
        this.xadesFileName = xadesFileName;
    }

    public void setXadesFileMimeType(String xadesFileMimeType)
    {
        this.xadesFileMimeType = xadesFileMimeType;
    }

    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        log.debug("Using XAdESSignatureFactory");

        SignatureResult signatureResult = new SignatureResult();
        
        // Signature data
        Provider provider = signatureOptions.getProvider();        
        X509Certificate certificate = signatureOptions.getCertificate();
        PrivateKey privateKey = signatureOptions.getPrivateKey();

        log.debug(provider.getName() + " provider found");
        
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

        // Retrieve DigiDoc configuration        
        ConfigManager conf = ConfigManager.getInstance();  
        
        // If the file to sign is big, prepare temporal files        
        File temporal = null;
        File ftoSign = new File("jar://data.xml");
        
        if (signatureOptions.getSwapToFile())
        {
            temporal = new File(OS.getSystemTmpDir() + "/signatureData.dat");
            OS.dumpToFile(temporal, signatureOptions.getDataToSign());
            xadesFileName = temporal.getAbsolutePath();
            ftoSign = temporal;
        }		

        // Check if input is a DigiDoc file for cosign        
        SignedDoc signedDoc = null;

        //TODO: This can cause problems with big file management
        // If byte[] is not retrieved, the stream gets empty when readSignedDoc
        // is executed
        
        byte[] data = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
        
        try
        {
        	DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        	documentBuilderFactory.setNamespaceAware(true);
        	DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        	Document current = documentBuilder.parse(new ByteArrayInputStream(data));
        	
        	NodeList docs = current.getElementsByTagNameNS("http://www.sk.ee/DigiDoc/v1.3.0#", "SignedDoc");
        	
        	if (docs.getLength() == 1)
        	{        	
        		DigiDocFactory digFac = ConfigHandler.getDigiDocFactory();
        		signedDoc = digFac.readSignedDoc(new ByteArrayInputStream(data));
        	}
        	else
        	{
        		throw new DigiDocException(-1, "", null);
        	}
        }
        catch (DigiDocException dde)
        {
            signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
            
            // Add a new reference in Bas64 and establish body data        
            DataFile df = signedDoc.addDataFile(ftoSign, this.xadesFileMimeType, DataFile.CONTENT_EMBEDDED_BASE64);
            
            signedDoc.getDataFile(0).setFileName(xadesFileName);
            signedDoc.getDataFile(0).setMimeType(xadesFileMimeType);
            
            if (!signatureOptions.getSwapToFile())
            {
                df.setBody(data);
                df.setSize(data.length);
            }            
        }
        
        // Prepare the signature        
        String[] roles;
        
        if (this.signerRole != null)
        {
            roles = new String[] { signerRole };
        }
        else
        {
            roles = new String[] {};
        }
        
        Signature signature = signedDoc.prepareSignature((X509Certificate) certificate, roles, null);
        CertValue certValue = null;

        // Sign
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
            log.error(LabelManager.get("ERROR_DDOC_SIGNATURE"));

            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_DDOC_SIGNATURE"));

            return signatureResult;
        }

        log.debug("Signing XAdES info. XAdES signature length " + res.length);

        // Add the signature to the signed doc
        signature.setSignatureValue(res);

        // Get the timestamp and add it
        int tsaCount = conf.getIntProperty("DIGIDOC_TSA_COUNT", 0);

        if (tsaCount != 0)
        {
            String tsaUrl = conf.getProperty("DIGIDOC_TSA1_URL");
            String tsa1_ca = conf.getProperty("DIGIDOC_TSA1_CA_CERT");
            
            byte[] signatureValue = signature.getSignatureValue().toString().getBytes();

            TSResponse response = TimeStampFactory.getTimeStampResponse(tsaUrl, signatureValue, true);

            X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);
            TSResponseToken responseToken = new TSResponseToken(response);
            
            TSResponse mmm = new TSResponse(Base64.decode(Base64.encodeBytes(response.getEncodedToken())));
            
            if (! responseToken.verify(xcaCert, signatureValue))
            {
                signatureResult.setValid(false);
                signatureResult.addError("Obtained timestamp is not valid");
                
                return signatureResult;                
            }
            
            TimestampInfo ts = new TimestampInfo("TS1", TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
            ts.setTimeStampResponse(response);
            ts.setSignature(signature);
            ts.setHash(responseToken.getMessageImprint());

            signature.addTimestampInfo(ts);


            if (tsa1_ca == null)
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERROR_DDOC_TSACA"));

                return signatureResult;
            }

            certValue = new CertValue();
            certValue.setType(CertValue.CERTVAL_TYPE_TSA);
            certValue.setCert(xcaCert);
            certValue.setId(signature.getId() + "-TSA_CERT");

            // Check the certificate validity against the timestamp
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
            // Add TSA certificate
            if (tsaCount != 0)
            {
                signature.addCertValue(certValue);
            }

            // OCSP validation
            if (conf.getProperty("DIGIDOC_CERT_VERIFIER").trim().equals("OCSP"))
            {
                signature.getConfirmation();
            }

            String tsaUrl = conf.getProperty("DIGIDOC_TSA1_URL");
            String tsa1_ca = conf.getProperty("DIGIDOC_TSA1_CA_CERT");
            
            byte[] completeCertificateRefs = signature.getUnsignedProperties()
                    .getCompleteCertificateRefs().toXML();

            byte[] completeRevocationRefs = signature.getUnsignedProperties()
                    .getCompleteRevocationRefs().toXML();

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

            X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);
            TSResponse response = TimeStampFactory.getTimeStampResponse(tsaUrl, refsOnlyData, true);
            TSResponseToken responseToken = new TSResponseToken(response);            

            if (! responseToken.verify(xcaCert, refsOnlyData))
            {
                signatureResult.setValid(false);
                signatureResult.addError("Obtained timestamp is not valid");

                return signatureResult;                
            }
            
            TimestampInfo ts = new TimestampInfo("TS2", TimestampInfo.TIMESTAMP_TYPE_REFS_ONLY);
            ts.setTimeStampResponse(response);
            ts.setSignature(signature);
            ts.setHash(responseToken.getMessageImprint());

            signature.addTimestampInfo(ts);

            log.debug("OCSP verification completed");

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

        signatureResult.setValid(true);

        // If we sign a big file, we write the result into a file and get back a FileInputStream
        File random = new File(OS.getSystemTmpDir() + "/signature.xsig");

        if (signatureOptions.getSwapToFile())
        {            
            signedDoc.writeToFile(random);
            signatureResult.setSignatureData(new FileInputStream(random));
        }
        else
        {
            signatureResult.setSignatureData(new ByteArrayInputStream(signedDoc.toXML().getBytes()));
        }

        // Remove temporal files for big file signature        
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
}
package es.uji.security.crypto.ocsp;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

import sun.misc.BASE64Encoder;
import sun.security.x509.AccessDescription;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;
import es.uji.security.crypto.OCSPResponseDetails;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.config.OS;
import es.uji.security.util.Base64;

public class OCSPChecker
{
    public static boolean compareDigests(byte[] dig1, byte[] dig2)
    {
        boolean ok = (dig1 != null) && (dig2 != null) && (dig1.length == dig2.length);

        for (int i = 0; ok && (i < dig1.length); i++)
        {
            if (dig1[i] != dig2[i])
            {
                ok = false;
            }
        }

        return ok;
    }

    private CertificateID generateCertificateID(X509Certificate certificate, X509Certificate caCertificate, Provider provider) throws CryptoCoreOCSPException
    {
        CertificateID certificateID = null;

        try
        {
            certificateID = new CertificateID(CertificateID.HASH_SHA1, caCertificate, certificate.getSerialNumber());
        }
        catch (OCSPException e)
        {
            throw new CryptoCoreOCSPException("Can not generate a valid certificate ID. CA certificate encoding is not valid", e);
		}

        return certificateID;
    }

    public OCSPResp sendOCSPRequest(String ocspURL, CertificateID certificateID,
            X509Certificate certificate) throws CryptoCoreOCSPException
    {
        try
        {
	        OCSPReqGenerator ocspRequest = new OCSPReqGenerator();
	        ocspRequest.addRequest(certificateID);
	
	        GeneralName name = new GeneralName(PrincipalUtil.getSubjectX509Principal(certificate));
	        ocspRequest.setRequestorName(name);
	
	        OCSPReq req = ocspRequest.generate();
	
	        return sendOCSPRequest(req, ocspURL);
        }
        catch (CertificateEncodingException cee)
        {
            throw new CryptoCoreOCSPException(
                    "Can not send OCSP request. Certificate encoding is not valid", cee);
        }
        catch (OCSPException oe)
        {
            throw new CryptoCoreOCSPException("Can not generate OCSP request", oe);
        }
    }
    
    public OCSPResp sendOCSPRequest(OCSPReq req, String ocspURL) throws CryptoCoreOCSPException
    {
        OCSPResp ocspResp = null;

        try
        {
            byte[] breq = req.getEncoded();
            URL url = new URL(ocspURL);
            URLConnection con = url.openConnection();
            con.setReadTimeout(10000);
            con.setConnectTimeout(10000);
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);

            // Send the OCSP request
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            OutputStream os = con.getOutputStream();
            os.write(breq);
            os.close();

            // Read the response
            byte[] bresp = OS.inputStreamToByteArray(con.getInputStream());

            ocspResp = new OCSPResp(bresp);
        }
        catch (IOException ioe)
        {
            throw new CryptoCoreOCSPException("Can not recover response from server " + ocspURL,
                    ioe);
        }

        return ocspResp;
    }

    public OCSPResp sendOCSPRequestPOST(String postURL, X509Certificate certificate) throws CryptoCoreOCSPException
    {
        OCSPResp ocspResp = null;

        try
        {
        	BASE64Encoder encoder=new BASE64Encoder();
        	String certBase64 = encoder.encodeBuffer(certificate.getEncoded());
        	
            URL url = new URL(postURL);
            URLConnection con = url.openConnection();
            con.setReadTimeout(10000);
            con.setConnectTimeout(10000);
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);

            con.setRequestProperty("Content-Type", "application/octet-stream");
            OutputStream os = con.getOutputStream();
            os.write(certBase64.getBytes());
            os.close();

            byte[] resp64 = OS.inputStreamToByteArray(con.getInputStream());
            byte[] bresp = Base64.decode(resp64);
            
            if (bresp.length==0)
            	ocspResp = new OCSPResp(new OCSPResponse(null));
            else
            	ocspResp = new OCSPResp(bresp);
        }
        catch (CertificateEncodingException cee)
        {
            throw new CryptoCoreOCSPException(
                    "Can not send OCSP request. Certificate encoding is not valid", cee);
        }
        catch (IOException ioe)
        {
            throw new CryptoCoreOCSPException("Can not recover response from server " + postURL,
                    ioe);
        }

        return ocspResp;
    }

    @SuppressWarnings( { "deprecation", "unchecked" })
    public OCSPResponseDetails getCertificateStatus(X509Certificate certificate,
            X509Certificate caCertificate, X509Certificate ocspCertificate, Provider provider)
    {
        OCSPResponseDetails responseDetails = new OCSPResponseDetails();
        String ocspURL = null;

        try
        {
            X509CertImpl certificateImpl = (X509CertImpl) certificate;
            AuthorityInfoAccessExtension authorityInfoAccessExtension = certificateImpl
                    .getAuthorityInfoAccessExtension();

            for (AccessDescription accessDescription : ((List<AccessDescription>) authorityInfoAccessExtension
                    .get(AuthorityInfoAccessExtension.DESCRIPTIONS)))
            {
                if (accessDescription.getAccessMethod().equals(AccessDescription.Ad_OCSP_Id))
                {
                    sun.security.x509.GeneralName generalName = accessDescription
                            .getAccessLocation();

                    if (generalName.getType() == GeneralNameInterface.NAME_URI)
                    {

                        URIName uri = (URIName) generalName.getName();
                        ocspURL = uri.getName();
                        break;
                    }
                }
            }
        }
        catch (Exception e)
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not recover OCSP URL from certificate");
        }

        if (ocspURL != null)
        {
            responseDetails = getCertificateStatus(ocspURL, certificate, caCertificate,
                    ocspCertificate, provider);
        }
        else
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not recover OCSP URL from certificate");
        }

        return responseDetails;
    }

    @SuppressWarnings("deprecation")
    public OCSPResponseDetails getCertificateStatus(String ocspURL, X509Certificate certificate,
            X509Certificate caCertificate, X509Certificate ocspCertificate, Provider provider)
    {
        OCSPResponseDetails responseDetails = new OCSPResponseDetails();

        CertificateID certificateID = null;

        try
        {
            certificateID = generateCertificateID(certificate, caCertificate, provider);
        }
        catch (CryptoCoreOCSPException ccoe)
        {
            responseDetails.setValid(false);
            responseDetails.addError(ccoe.getMessage());
            return responseDetails;
        }

        OCSPResp resp = null;

        try
        {
        	ConfigManager conf = ConfigManager.getInstance();
        	String type = conf.getProperty("DIGIDOC_CERT_VERIFIER");
        	
        	if (type.equals("POST"))
        	{
        		resp = sendOCSPRequestPOST(conf.getProperty("DIGIDOC_CERT_VERIFIER_URL"), certificate);
        		
        		if (resp==null)
        		{
                    responseDetails.setValid(false);
                    responseDetails.addError(("Server does not know about this certificate"));
                    return responseDetails;
        		}
        	}
       		else if (type.equals("OCSP"))
       		{
        		resp = sendOCSPRequest(ocspURL, certificateID, certificate);
       		}
        }
        catch (CryptoCoreOCSPException ccoe)
        {
            responseDetails.setValid(false);
            responseDetails.addError(ccoe.getMessage());
            return responseDetails;
        }

        if (resp == null)
        {
        	responseDetails.setValid(false);
        	responseDetails.addError("An internal error occured in the OCSP Server!");
        	return responseDetails;
        }
        
        try
        {
            responseDetails.setResponseData(resp.getEncoded());
        }
        catch (IOException ioe)
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not get encoded content from OCSP respose");
            return responseDetails;
        }


        if (resp.getStatus() != OCSPRespStatus.SUCCESSFUL)
        {
            responseDetails.setValid(false);

            switch (resp.getStatus())
            {
            case OCSPRespStatus.INTERNAL_ERROR:
                responseDetails.addError("An internal error occured in the OCSP Server");
                break;
            case OCSPRespStatus.MALFORMED_REQUEST:
                responseDetails.addError("Your request did not fit the RFC 2560 syntax");
                break;
            case OCSPRespStatus.SIGREQUIRED:
                responseDetails.addError("Your request was not signed");
                break;
            case OCSPRespStatus.TRY_LATER:
                responseDetails.addError("The server was too busy to answer you");
                break;
            case OCSPRespStatus.UNAUTHORIZED:
                responseDetails.addError("The server could not authenticate you");
                break;
            default:
                responseDetails.addError("Unknown OCSPResponse status code " + resp.getStatus());
            }

            return responseDetails;
        }

        // Read the info from the response
        BasicOCSPResp basicOCSPResp = null;

        try
        {
            basicOCSPResp = (BasicOCSPResp) resp.getResponseObject();
        }
        catch (OCSPException oe)
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not retrieve basic reponse object from server response");
            return responseDetails;
        }

        try
        {
            if (!basicOCSPResp.verify(ocspCertificate.getPublicKey(), provider.getName()))
            {
                responseDetails.setValid(false);
                responseDetails.addError("OCSP Signature verification error");
                
                return responseDetails;
            }
        }
        catch (NoSuchProviderException nspe)
        {
            responseDetails.setValid(false);
            responseDetails.addError("OCSP response verification error. Provider not available");
            return responseDetails;
        }
        catch (OCSPException oe)
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not verify OCSP response");
            return responseDetails;
        }

        SingleResp[] sresp = basicOCSPResp.getResponseData().getResponses();

        boolean validationOk = false;
        for (int i = 0; i < sresp.length; i++)
        {
            CertificateID id = sresp[i].getCertID();

            if (id != null)
            {
                if (certificateID.getHashAlgOID().equals(id.getHashAlgOID())
                        && certificateID.getSerialNumber().equals(id.getSerialNumber())
                        && compareDigests(certificateID.getIssuerKeyHash(), id.getIssuerKeyHash())
                        && compareDigests(certificateID.getIssuerNameHash(), id.getIssuerNameHash()))
                {
                    validationOk = true;
                    Object certStatus = sresp[i].getCertStatus();

                    if (certStatus != null)
                    {
                        if (certStatus instanceof RevokedStatus)
                        {
                            responseDetails.setValid(false);
                            responseDetails.addError("Certificate has been revoked");
                            return responseDetails;
                        }
                        if (certStatus instanceof UnknownStatus)
                        {
                            responseDetails.setValid(false);
                            responseDetails.addError("Certificate status is unknown");
                            return responseDetails;
                        }
                    }

                    break;
                }
            }
        }

        if (!validationOk)
        {
            responseDetails.setValid(false);
            responseDetails.addError("Bad OCSP response status");
            return responseDetails;
        }

        responseDetails.setValid(true);
        return responseDetails;
    }

    private void showStatus(OCSPResponseDetails responseDetails)
    {
        if (responseDetails.isValid())
        {
            System.out.println("OK");
        }
        else
        {
            for (String e : responseDetails.getErrors())
            {
                System.out.println(e);
            }
        }
    }

    public static void main(String[] args) throws CertificateException, KeyStoreException,
            NoSuchAlgorithmException, IOException
    {
        Provider provider = new BouncyCastleProvider();

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(provider);
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        
        String ocspURL = "http://ocsp.accv.es";

        X509Certificate cagvaCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream(
                        "src/main/resources/cagva.pem"));
        X509Certificate accvCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream(
                        "src/main/resources/accv-ca2.pem"));
        X509Certificate ocspCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream(
                        "src/main/resources/ocsp-gva.crt"));
        
        
        X509Certificate fnmtCertificate = (X509Certificate) certificateFactory
        .generateCertificate(new FileInputStream(
        		"src/main/resources/fnmt-ca.der"));        
        X509Certificate ocspFnmtCertificate = (X509Certificate) certificateFactory
		.generateCertificate(new FileInputStream(
        		"src/main/resources/fnmt-ocsp.cer")); 

        OCSPChecker oscp = new OCSPChecker();
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/fnmt.p12"), "makeall"
                .toCharArray());
        X509Certificate fnmt = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        oscp.showStatus(oscp.getCertificateStatus ("", fnmt, fnmtCertificate,
        		ocspFnmtCertificate, provider));
        
        /*
        
        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_firma.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaFirma = (X509Certificate) ks
                .getCertificate(ks.aliases().nextElement());
        oscp.showStatus(oscp.getCertificateStatus(cagvaFirma, cagvaCertificate, ocspCertificate, provider));
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, cagvaFirma, cagvaCertificate,
                ocspCertificate, provider));
        
        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_cifrado.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, cagvaCifrado, cagvaCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_firma.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, cagvaFirmaRevocado, cagvaCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_cifrado.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, cagvaCifradoRevocado, cagvaCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_firma.p12"), "1234"
                .toCharArray());
        X509Certificate accvFirma = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, accvFirma, accvCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_cifrado.p12"), "1234"
                .toCharArray());
        X509Certificate accvCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, accvCifrado, accvCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_F2.p12"), "AEATPF_F2".toCharArray());
        X509Certificate accvFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, accvFirmaRevocado, accvCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_C2.p12"), "AEATPF_C2".toCharArray());
        X509Certificate accvCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        oscp.showStatus(oscp.getCertificateStatus(ocspURL, accvCifradoRevocado, accvCertificate,
                ocspCertificate, provider));
                */
    }
}
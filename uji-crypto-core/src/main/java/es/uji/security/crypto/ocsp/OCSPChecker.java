package es.uji.security.crypto.ocsp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
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

import es.uji.security.crypto.OCSPResponseDetails;
import es.uji.security.util.OS;

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

    private CertificateID generateCertificateID(X509Certificate certificate,
            X509Certificate caCertificate, Provider provider) throws CertificateEncodingException,
            NoSuchAlgorithmException
    {
        X509Principal issuerName = PrincipalUtil.getSubjectX509Principal(caCertificate);

        MessageDigest digest = MessageDigest.getInstance("1.3.14.3.2.26", provider);
        digest.update(issuerName.getEncoded());

        ASN1OctetString issuerNameHash = new BERConstructedOctetString(digest.digest());

        byte[] arr = caCertificate.getExtensionValue("2.5.29.14");
        byte[] arr2 = new byte[arr.length - 4];
        System.arraycopy(arr, 4, arr2, 0, arr2.length);
        ASN1OctetString issuerKeyHash = new BERConstructedOctetString(arr2);

        CertID cerid = new CertID(new AlgorithmIdentifier("1.3.14.3.2.26"), issuerNameHash,
                issuerKeyHash, new DERInteger(certificate.getSerialNumber()));

        return new CertificateID(cerid);
    }

    private OCSPResp sendOCSPRequest(String ocspURL, CertificateID certificateID,
            X509Certificate certificate) throws CertificateEncodingException, OCSPException,
            IOException
    {
        OCSPReqGenerator ocspRequest = new OCSPReqGenerator();
        ocspRequest.addRequest(certificateID);

        GeneralName name = new GeneralName(PrincipalUtil.getSubjectX509Principal(certificate));
        ocspRequest.setRequestorName(name);

        OCSPReq req = ocspRequest.generate();

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

        return new OCSPResp(bresp);
    }

    @SuppressWarnings("deprecation")
    public OCSPResponseDetails getCertificateStatus(String ocspURL, X509Certificate certificate,
            X509Certificate caCertificate, X509Certificate ocspCertificate, Provider provider)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException, OCSPException, NoSuchProviderException
    {
        CertificateID certificateID = generateCertificateID(certificate, caCertificate, provider);
        OCSPResp resp = sendOCSPRequest(ocspURL, certificateID, certificate);

        OCSPResponseDetails responseDetails = new OCSPResponseDetails();
        responseDetails.setResponseData(resp.getEncoded());

        if (resp == null)
        {
            responseDetails.setValid(false);
            responseDetails.addError("An internal error occured in the OCSP Server!");
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
        BasicOCSPResp basicOCSPResp = (BasicOCSPResp) resp.getResponseObject();

        if (!basicOCSPResp.verify(ocspCertificate.getPublicKey(), provider.getName()))
        {
            responseDetails.setValid(false);
            responseDetails.addError("OCSP Signature verification error");
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

    public static void main(String[] args) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, FileNotFoundException, IOException, NoSuchProviderException,
            OCSPException
    {
        Provider provider = new BouncyCastleProvider();

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(provider);
        }

        String ocspURL = "http://ocsp.accv.es";

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cagvaCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream(
                        "../uji-config/src/main/resources/cagva.pem"));
        X509Certificate accvCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream(
                        "../uji-config/src/main/resources/accv-ca2.pem"));
        X509Certificate ocspCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream(
                        "../uji-config/src/main/resources/ocsp-gva.crt"));

        OCSPChecker oscp = new OCSPChecker();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_firma.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaFirma = (X509Certificate) ks
                .getCertificate(ks.aliases().nextElement());
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
    }
}
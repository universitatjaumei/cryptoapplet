package es.uji.security.crypto.jxades;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier;
import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifierImpl;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_EPES;
import net.java.xades.security.xml.XAdES.XMLAdvancedSignature;
import net.java.xades.util.XMLUtils;

import org.w3c.dom.Element;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.util.OS;
import es.uji.security.util.i18n.LabelManager;

public class JXAdESSignatureFactory implements ISignFormatProvider
{
    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        byte[] data = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
        X509Certificate certificate = signatureOptions.getCertificate();
        PrivateKey privateKey = signatureOptions.getPrivateKey();

        ByteArrayInputStream originalData = new ByteArrayInputStream(data);

        SignatureResult signatureResult = new SignatureResult();

        if (certificate == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_FACTURAE_NOCERT"));

            return signatureResult;
        }

        if (privateKey == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_FACTURAE_NOKEY"));

            return signatureResult;
        }

        // Load XML data
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Element element = db.parse(originalData).getDocumentElement();

        // Create a XAdES-EPES profile
        XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, element);

        // SigningCertificate. Check the certificate validity (local)
        try
        {
            certificate.checkValidity();
        }
        catch (CertificateException cex)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_CERTIFICATE_EXPIRED"));

            return signatureResult;
        }

        xades.setSigningCertificate(certificate);

        SignaturePolicyIdentifier spi = new SignaturePolicyIdentifierImpl(false);

        // Set SignaturePolicyIdentifier
        spi.setIdentifier("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf");
        spi.setDescription("Pol\u00edtica de firma electr\u00f3nica para facturaci\u00f3n electr\u00f3nica con formato Facturae");

        xades.setSignaturePolicyIdentifier(spi);

        // Sign data
        XMLAdvancedSignature xmlSignature = XMLAdvancedSignature.newInstance(xades);

        try
        {
            String id = UUID.randomUUID().toString();
            
            xmlSignature.sign(certificate, privateKey, Arrays.asList(new String[] { "" }), id,
                    "http://tss.accv.es:8318/tsa");
        }
        catch (MarshalException me)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_FACTURAE_SIGNATURE"));

            return signatureResult;
        }
        catch (XMLSignatureException xmlse)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_FACTURAE_SIGNATURE"));

            return signatureResult;
        }
        catch (GeneralSecurityException gse)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_FACTURAE_SIGNATURE"));

            return signatureResult;
        }

        // Return Results
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BufferedOutputStream bos = new BufferedOutputStream(out);

        XMLUtils.writeXML(bos, xmlSignature.getBaseElement(), false);
        bos.flush();

        signatureResult.setValid(true);
        signatureResult.setSignatureData(new ByteArrayInputStream(out.toString().getBytes()));

        return signatureResult;
    }
}

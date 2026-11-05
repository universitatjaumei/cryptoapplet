package es.uji.security.crypto.facturae;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.DigestMethod;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.jxades.JXAdESSignatureFactory;

public class FacturaeSignatureFactory implements ISignFormatProvider
{
    public static final String POLICY_IDENTIFIER = "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf";
    public static final String POLICY_DESCRIPTION = "Pol\u00edtica de firma electr\u00f3nica para facturaci\u00f3n electr\u00f3nica con formato Facturae";

    // SHA-1 of the Facturae v3.1 signature policy document (Base64)
    public static final String POLICY_HASH = "Ohixl6upD6av8N7pEvDABhEL6hM=";
    public static final String POLICY_HASH_ALGORITHM = DigestMethod.SHA1;

    public static final String DEFAULT_SIGNER_ROLE = "emisor";

    // Signer roles allowed by the Facturae signature policy
    public static final List<String> VALID_SIGNER_ROLES = Arrays.asList("emisor", "receptor",
            "tercero", "supplier", "customer", "thirdparty");

    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        byte[] data = OS.inputStreamToByteArray(signatureOptions.getDataToSign());

        // Check if input data is already signed
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

        Document document = documentBuilder.parse(new ByteArrayInputStream(data));

        NodeList result = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                "Signature");
        int numSignatures = result.getLength();

        if (numSignatures > 0)
        {
            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(false);
            signatureResult.addError("CoSign for Facturae not supported");

            return signatureResult;
        }

        String signerRole = signatureOptions.getSignerRole();

        if (signerRole == null)
        {
            signatureOptions.setSignerRole(DEFAULT_SIGNER_ROLE);
        }
        else if (!VALID_SIGNER_ROLES.contains(signerRole))
        {
            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(false);
            signatureResult.addError("Invalid Facturae signer role '" + signerRole
                    + "'. Allowed values: " + VALID_SIGNER_ROLES);

            return signatureResult;
        }

        // Call jXAdES format signature
        signatureOptions.setCoSignEnabled(false);
        signatureOptions.setPolicyIdentifier(POLICY_IDENTIFIER);
        signatureOptions.setPolicyDescription(POLICY_DESCRIPTION);
        signatureOptions.setPolicyHash(POLICY_HASH);
        signatureOptions.setPolicyHashAlgorithm(POLICY_HASH_ALGORITHM);
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));

        JXAdESSignatureFactory signatureFactory = new JXAdESSignatureFactory();

        return signatureFactory.formatSignature(signatureOptions);
    }
}

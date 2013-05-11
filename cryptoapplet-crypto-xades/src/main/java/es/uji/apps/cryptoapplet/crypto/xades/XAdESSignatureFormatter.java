package es.uji.apps.cryptoapplet.crypto.xades;

import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.exceptions.SignatureException;
import es.uji.apps.cryptoapplet.crypto.signature.format.AbstractSignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureOptions;
import es.uji.apps.cryptoapplet.utils.StreamUtils;
import net.java.xades.security.xml.XAdES.*;
import net.java.xades.util.XMLUtils;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.*;

public class XAdESSignatureFormatter extends AbstractSignatureFormatter implements SignatureFormatter
{
    private Map<String, String> options;

    public XAdESSignatureFormatter(X509Certificate certificate, PrivateKey privateKey, Provider provider)
            throws SignatureException
    {
        super(certificate, privateKey, provider);
    }

    @Override
    public byte[] format(SignatureOptions signatureOptions) throws SignatureException
    {
        checkSignatureOptions(signatureOptions);

        byte[] data = StreamUtils.inputStreamToByteArray(signatureOptions.getDataToSign());

        try
        {
            // Load XML data
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Element element = db.parse(new ByteArrayInputStream(data)).getDocumentElement();

            // Create a XAdES-EPES profile
            XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, element);
            xades.setSigningCertificate(certificate);

            SignaturePolicyIdentifier spi;

            Configuration configuration = signatureOptions.getConfiguration();
            es.uji.apps.cryptoapplet.config.model.Format formatter = configuration
                    .getFormatRegistry().getFormat("XADES");
            options = formatter.getConfigurationOptions();

            if (options.get("policyIdentifier") != null)
            {
                spi = new SignaturePolicyIdentifierImpl(false);
                spi.setIdentifier(options.get("policyIdentifier"));
                spi.setDescription(options.get("policyDescription"));
                xades.setSignaturePolicyIdentifier(spi);
            }

            if (options.get("signerRole") != null)
            {
                SignerRole role = new SignerRoleImpl();
                role.setClaimedRole(new ArrayList<String>(Arrays.asList(new String[]{options
                        .get("signerRole")})));

                xades.setSignerRole(role);
            }

            // Sign data
            XMLAdvancedSignature xmlSignature = XMLAdvancedSignature.newInstance(xades);

            NodeList result = element.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                    "Signature");
            int numSignature = result.getLength();

            List<String> references = new ArrayList<String>();

            // If no there are no references, add enveloped reference
            if (signatureOptions.isEnveloped())
            {
                references.add("");
            }
            else
            {
                if (options.get("references") != null)
                {
                    references = Arrays.asList(options.get("references").split(","));
                }
            }

            // If enveloped+cosig construct special transformation
            if (signatureOptions.isEnveloped() && signatureOptions.isCoSignEnabled())
            {
                XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
                DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1,
                        null);

                Transform transform = xmlSignatureFactory.newTransform(Transform.XPATH,
                        new XPathFilterParameterSpec("not(ancestor-or-self::dsig:Signature)",
                                Collections.singletonMap("dsig", XMLSignature.XMLNS)));

                Reference reference = xmlSignatureFactory.newReference("", digestMethod,
                        Collections.singletonList(transform), null, null);

                xmlSignature.sign(certificate, privateKey, SignatureMethod.RSA_SHA1,
                        Arrays.asList(new Object[]{reference}), "S" + numSignature);
            }
            else
            {
                xmlSignature.sign(certificate, privateKey, SignatureMethod.RSA_SHA1, references,
                        "S" + numSignature);
            }

            // Return Results
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            BufferedOutputStream bos = new BufferedOutputStream(out);

            XMLUtils.writeXML(bos, xmlSignature.getBaseElement(), false);
            bos.flush();

            return out.toByteArray();
        }
        catch (Exception e)
        {
            throw new SignatureException(e);
        }
    }
}

package es.uji.apps.cryptoapplet.crypto.xades;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier;
import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifierImpl;
import net.java.xades.security.xml.XAdES.SignerRole;
import net.java.xades.security.xml.XAdES.SignerRoleImpl;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_EPES;
import net.java.xades.security.xml.XAdES.XMLAdvancedSignature;
import net.java.xades.util.XMLUtils;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.uji.apps.cryptoapplet.crypto.BaseFormatter;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class XAdESFormatter extends BaseFormatter implements Formatter
{
    public XAdESFormatter(X509Certificate certificate, PrivateKey privateKey, Provider provider)
            throws SignatureException
    {
        super(certificate, privateKey, provider);
    }

    @Override
    public SignatureResult format(SignatureOptions signatureOptions) throws SignatureException
    {
        checkSignatureOptions(signatureOptions);

        byte[] data = StreamUtils.inputStreamToByteArray(signatureOptions.getDataToSign());

        // TODO: KeyStore loaded in device init must store the reference
        Security.removeProvider(provider.getName());
        Security.insertProviderAt(provider, 1);

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

            if (signatureOptions.getPolicyIdentifier() != null)
            {
                spi = new SignaturePolicyIdentifierImpl(false);
                spi.setIdentifier(signatureOptions.getPolicyIdentifier());
                spi.setDescription(signatureOptions.getPolicyDescription());
                xades.setSignaturePolicyIdentifier(spi);
            }

            if (signatureOptions.getSignerRole() != null)
            {
                SignerRole role = new SignerRoleImpl();
                role.setClaimedRole(new ArrayList<String>(Arrays
                        .asList(new String[] { signatureOptions.getSignerRole() })));

                xades.setSignerRole(role);
            }

            // Sign data
            XMLAdvancedSignature xmlSignature = XMLAdvancedSignature.newInstance(xades);

            NodeList result = element.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                    "Signature");
            int numSignature = result.getLength();

            List<String> references = signatureOptions.getReferences();

            // If no there are no references, add enveloped reference
            if (signatureOptions.isEnveloped() || references.isEmpty())
            {
                references.clear();
                references.add("");
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
                        Arrays.asList(new Object[] { reference }), "S" + numSignature);
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

            SignatureResult signatureResult = new SignatureResult(true);
            signatureResult.setSignatureData(new ByteArrayInputStream(out.toByteArray()));
            
            return signatureResult;
        }
        catch (Exception e)
        {
            throw new SignatureException(e);
        }
    }
}

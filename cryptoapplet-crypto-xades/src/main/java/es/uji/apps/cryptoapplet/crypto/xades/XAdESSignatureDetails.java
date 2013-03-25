package es.uji.apps.cryptoapplet.crypto.xades;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;
import es.uji.apps.cryptoapplet.crypto.signature.details.SignatureDetails;
import es.uji.apps.cryptoapplet.crypto.signature.details.SignatureDetailsGenerator;
import org.bouncycastle.jce.X509Principal;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

public class XAdESSignatureDetails implements SignatureDetailsGenerator
{
    private final String defaultNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private final String xadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";

    public List<SignatureDetails> getDetails(byte[] data) throws CryptoAppletException
    {
        List<SignatureDetails> result = new ArrayList<SignatureDetails>();

        if (data != null && data.length > 0)
        {
            try
            {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder db = dbf.newDocumentBuilder();
                org.w3c.dom.Document d = db.parse(new ByteArrayInputStream(data));

                NodeList signatures = d.getElementsByTagNameNS(defaultNamespace, "Signature");

                for (int i = 0; i < signatures.getLength(); i++)
                {
                    Element currentSignature = (Element) signatures.item(i);

                    NodeList nlCN = currentSignature.getElementsByTagNameNS(defaultNamespace,
                            "X509SubjectName");
                    NodeList nlTime = currentSignature.getElementsByTagNameNS(xadesNamespace,
                            "SigningTime");
                    NodeList nlRole = currentSignature.getElementsByTagNameNS(xadesNamespace,
                            "ClaimedRole");

                    SignatureDetails signatureDetailInformation = new SignatureDetails();

                    if (nlCN != null && nlCN.getLength() > 0
                            && nlCN.item(0).getFirstChild() != null)
                    {
                        String nodeValue = nlCN.item(0).getFirstChild().getNodeValue();

                        if (nodeValue != null)
                        {
                            X509Principal principal = new X509Principal(nodeValue);
                            Vector<String> values = principal.getValues(X509Principal.CN);
                            signatureDetailInformation.setSignerCN(values.get(0));
                        }
                    }

                    if (nlTime != null && nlTime.getLength() > 0
                            && nlTime.item(0).getFirstChild() != null)
                    {
                        String timeString = nlTime.item(0).getFirstChild().getNodeValue();
                        signatureDetailInformation.setSignatureTimeAsXMLDateTime(timeString);
                    }

                    if (nlRole != null && nlRole.getLength() > 0
                            && nlRole.item(0).getFirstChild() != null)
                    {
                        signatureDetailInformation.setSigningRole(nlRole.item(0).getFirstChild()
                                .getNodeValue());
                    }

                    result.add(signatureDetailInformation);
                }
            }
            catch (Exception e)
            {
                throw new CryptoAppletException("Error parsing document");
            }
        }

        return result;
    }
}
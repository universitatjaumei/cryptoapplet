package es.uji.security.crypto;

import java.io.ByteArrayInputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.jce.X509Principal;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.uji.security.util.ISO8601DateParser;

public class SignatureDetailInformation
{    
    private String signerCN;
    private Date signatureTime;
    private String signingRole;

    public String getSignerCN()
    {
        return signerCN;
    }

    public void setSignerCN(String signerCN)
    {
        this.signerCN = signerCN;
    }

    public Date getSignatureTime()
    {
        return signatureTime;
    }

    public void setSignatureTime(Date signatureTime)
    {
        this.signatureTime = signatureTime;
    }

    public void setSignatureTimeAsXMLDateTime(String signatureTime) throws ParseException
    {
        this.signatureTime = ISO8601DateParser.parse(signatureTime);
    }

    public String getSigningRole()
    {
        return signingRole;
    }

    public void setSigningRole(String signingRole)
    {
        this.signingRole = signingRole;
    }

    public String toString()
    {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Signer CN: ").append(this.signerCN).append("\n");
        stringBuilder.append("Signature time: ").append(this.signatureTime).append("\n");
        stringBuilder.append("Signer role: ").append(this.signingRole);

        return stringBuilder.toString();
    }

    public String getSignatureTimeAsXMLDateTime()
    {
        return ISO8601DateParser.toString(this.signatureTime);
    }

    @SuppressWarnings("unchecked")
    public static List<SignatureDetailInformation> getSignatureDetailInformation(byte[] data,
            String xadesNamespace) throws CryptoCoreException
    {
        List<SignatureDetailInformation> result = new ArrayList<SignatureDetailInformation>();

        if (data != null && data.length > 0)
        {
            String defaultNamespace = "http://www.w3.org/2000/09/xmldsig#";

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

                    SignatureDetailInformation signatureDetailInformation = new SignatureDetailInformation();

                    if (nlCN != null && nlCN.getLength() > 0
                            && nlCN.item(0).getFirstChild() != null)
                    {
                        String nodeValue = nlCN.item(0).getFirstChild().getNodeValue();

                        if (nodeValue != null)
                        {
                            X509Principal principal = new X509Principal(nodeValue);
                            Vector values = principal.getValues();
                            
                            if (values != null && values.size()>0)
                            {
                                signatureDetailInformation.setSignerCN((String) values.get(values.size()-1));
                            }
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
                throw new CryptoCoreException("Error parsing document");
            }
        }

        return result;
    }
}
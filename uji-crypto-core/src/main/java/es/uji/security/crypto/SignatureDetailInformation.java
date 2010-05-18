package es.uji.security.crypto;

import java.io.ByteArrayInputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SignatureDetailInformation
{
    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");

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
        this.signatureTime = simpleDateFormat.parse(signatureTime);
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
        return simpleDateFormat.format(this.signatureTime);
    }

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
                            String[] fields = nodeValue.split(",");

                            for (String f : fields)
                            {
                                if (f.trim().startsWith("CN="))
                                {
                                    signatureDetailInformation.setSignerCN(f.trim().substring(3));
                                }
                            }
                        }
                    }

                    if (nlTime != null && nlTime.getLength() > 0
                            && nlTime.item(0).getFirstChild() != null)
                    {
                        signatureDetailInformation.setSignatureTimeAsXMLDateTime(nlTime.item(0)
                                .getFirstChild().getNodeValue());
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
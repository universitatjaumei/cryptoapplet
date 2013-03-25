package es.uji.apps.cryptoapplet.crypto.signature.details;

import es.uji.apps.cryptoapplet.utils.ISO8601DateParser;

import java.text.ParseException;
import java.util.Date;

public class SignatureDetails
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
}
package es.uji.apps.cryptoapplet.ui.service.model;

import java.math.BigInteger;

public class Certificate
{
    private String dn;
    private BigInteger serial;

    public Certificate(String dn, BigInteger serial)
    {
        this.dn = dn;
        this.serial = serial;
    }

    public String getDn()
    {
        return dn;
    }

    public void setDn(String dn)
    {
        this.dn = dn;
    }

    public BigInteger getSerial()
    {
        return serial;
    }

    public void setSerial(BigInteger serial)
    {
        this.serial = serial;
    }
}

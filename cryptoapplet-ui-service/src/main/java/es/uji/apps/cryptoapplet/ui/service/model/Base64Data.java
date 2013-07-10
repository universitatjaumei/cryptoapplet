package es.uji.apps.cryptoapplet.ui.service.model;

import es.uji.apps.cryptoapplet.utils.Base64;

public class Base64Data
{
    private String data;

    public Base64Data(byte[] rawData)
    {
        data = Base64.encodeBytes(rawData);
    }

    public String getData()
    {
        return data;
    }
}

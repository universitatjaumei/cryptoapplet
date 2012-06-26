package es.uji.apps.cryptoapplet.keystore.pkcs11.devices;

import java.util.ArrayList;
import java.util.List;

import es.uji.apps.cryptoapplet.keystore.pkcs11.PKCS11Configurable;
import es.uji.apps.cryptoapplet.keystore.pkcs11.PKCS11Device;

public class DNIe extends PKCS11Device implements PKCS11Configurable
{
    @Override
    public byte[] getPKCS11Configuration()
    {
        StringBuilder config = new StringBuilder();
        config.append("name = DNIe").append("\n");
        config.append("library = " + getPKCS11Library());

        return config.toString().getBytes();
    }

    @Override
    public String getPKCS11Library()
    {
        List<String> guessPaths = new ArrayList<String>();
        guessPaths.add("/usr/local/lib/");
        guessPaths.add("/usr/lib/");
        guessPaths.add("/usr/lib/pkcs11/");

        return getFirstExistingFileName(guessPaths, "opensc-pkcs11.so");
    }
}
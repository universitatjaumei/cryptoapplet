package es.uji.security.keystore.pkcs11;

public interface PKCS11Configurable
{
    String getPKCS11Library();

    byte[] getPKCS11Configuration();
}

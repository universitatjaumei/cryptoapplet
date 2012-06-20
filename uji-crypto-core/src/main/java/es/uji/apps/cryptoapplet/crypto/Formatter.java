package es.uji.apps.cryptoapplet.crypto;

public interface Formatter
{
    public SignatureResult format(SignatureOptions signatureOptions)
            throws CryptoAppletCoreException; 
}
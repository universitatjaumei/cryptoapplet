package es.uji.apps.cryptoapplet.crypto.signature;

public enum SignatureFormat
{
    RAW
    {
        public String toString()
        {
            return "es.uji.apps.cryptoapplet.crypto.raw.RawFormatter";
        }
    },
    CMS
    {
        public String toString()
        {
            return "es.uji.apps.cryptoapplet.crypto.cms.CMSFormatter";
        }
    },
    XMLSIGNATURE
    {
        public String toString()
        {
            return "es.uji.apps.cryptoapplet.crypto.xmlsignature.XMLSignatureFormatter";
        }
    },
    XADES
    {
        public String toString()
        {
            return "es.uji.apps.cryptoapplet.crypto.xades.XAdESFormatter";
        }
    },
    PADES
    {
        public String toString()
        {
            return "es.uji.apps.cryptoapplet.crypto.pdf.PAdESFormatter";
        }
    },
    ODF
    {
        public String toString()
        {
            return "es.uji.apps.cryptoapplet.crypto.xmlsignature.odf.ODFFormatter";
        }
    },
    FACTURAE
    {
        public String toString()
        {
            return "es.uji.apps.cryptoapplet.crypto.xades.facturae.FacturaeFormatter";
        }
    }
}
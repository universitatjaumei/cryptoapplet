package es.uji.apps.cryptoapplet.crypto;

public enum SignatureFormat
{
    RAW {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.raw.RawSignatureFactory"; 
        }
    },
    CMS {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.cms.CMSSignatureFactory"; 
        }
    }, 
    CMS_HASH {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.cms.CMSSignatureFactory"; 
        }
    }, 
    XMLSIGNATURE {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.xmldsign.XMLDsigSignatureFactory"; 
        }
    }, 
    XADES_JXADES {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.jxades.JXAdESSignatureFactory"; 
        }
    }, 
    XADES_OPENXADES {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.openxades.OpenXAdESSignatureFactory"; 
        }
    }, 
    PDF {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.pdf.PDFSignatureFactory"; 
        }
    }, 
    ODF {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.xmldsign.odf.ODFSignatureFactory"; 
        }
    },
    FACTURAE {
        public String toString() {
            return "es.uji.apps.cryptoapplet.crypto.facturae.FacturaeSignatureFactory"; 
        }
    }  
}

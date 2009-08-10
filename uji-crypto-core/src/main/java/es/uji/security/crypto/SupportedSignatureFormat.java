package es.uji.security.crypto;

public enum SupportedSignatureFormat
{
    RAW {
        public String toString() {
            return "es.uji.security.crypto.raw.RawSignatureFactory"; 
        }
    },
    CMS {
        public String toString() {
            return "es.uji.security.crypto.cms.CMSSignatureFactory"; 
        }
    }, 
    CMS_HASH {
        public String toString() {
            return "es.uji.security.crypto.cms.CMSSignatureFactory"; 
        }
    }, 
    XADES {
        public String toString() {
            return "es.uji.security.crypto.openxades.OpenXAdESSignatureFactory"; 
        }
    }, 
    XADES_COSIGN {
        public String toString() {
            return "es.uji.security.crypto.openxades.OpenXAdESCoSignatureFactory"; 
        }
    }, 
    PDF {
        public String toString() {
            return "es.uji.security.crypto.pdf.PDFSignatureFactory"; 
        }
    }, 
    FACTURAE {
        public String toString() {
            return "es.uji.security.crypto.jxades.JXAdESSignatureFactory"; 
        }
    }, 
    XMLDSIG {
        public String toString() {
            return "es.uji.security.crypto.xmldsign.XMLDsigSignatureFactory"; 
        }
    } 
}

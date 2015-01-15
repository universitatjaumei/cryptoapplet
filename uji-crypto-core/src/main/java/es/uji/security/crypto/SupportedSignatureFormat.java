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
    XMLSIGNATURE {
        public String toString() {
            return "es.uji.security.crypto.xmldsign.XMLDsigSignatureFactory"; 
        }
    }, 
    JXADES {
        public String toString() {
            return "es.uji.security.crypto.jxades.JXAdESSignatureFactory"; 
        }
    }, 
    XADES {
        public String toString() {
            return "es.uji.security.crypto.openxades.OpenXAdESSignatureFactory";
        }
    }, 
    PDF {
        public String toString() {
            return "es.uji.security.crypto.pdf.PDFSignatureFactory"; 
        }
    }, 
    ODF {
        public String toString() {
            return "es.uji.security.crypto.xmldsign.odf.ODFSignatureFactory"; 
        }
    },
    FACTURAE {
        public String toString() {
            return "es.uji.security.crypto.facturae.FacturaeSignatureFactory"; 
        }
    }  
}

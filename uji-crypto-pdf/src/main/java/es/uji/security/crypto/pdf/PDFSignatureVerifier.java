package es.uji.security.crypto.pdf;

/**
 * iText is used, documentation is: How to verify
 * 
 * Verifying is a three step process:
 * 
 * Was the document changed? What revision does the signature cover? Does the signature cover all
 * the document? Can the signature certificates be verified in your trusted identities store?
 * 
 * Here's an example on how to do it:
 * 
 * KeyStore kall = PdfPKCS7.loadCacertsKeyStore(); PdfReader reader = new
 * PdfReader("my_signed_doc.pdf"); AcroFields af = reader.getAcroFields(); ArrayList names =
 * af.getSignatureNames(); for (int k = 0; k < names.size(); ++k) { String name =
 * (String)names.get(k); System.out.println("Signature name: " + name);
 * System.out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
 * System.out.println("Document revision: " + af.getRevision(name) + " of " +
 * af.getTotalRevisions()); // Start revision extraction FileOutputStream out = new
 * FileOutputStream("revision_" + af.getRevision(name) + ".pdf"); byte bb[] = new byte[8192];
 * InputStream ip = af.extractRevision(name); int n = 0; while ((n = ip.read(bb)) > 0) out.write(bb,
 * 0, n); out.close(); ip.close(); // End revision extraction PdfPKCS7 pk =
 * af.verifySignature(name); Calendar cal = pk.getSignDate(); Certificate pkc[] =
 * pk.getCertificates(); System.out.println("Subject: " +
 * PdfPKCS7.getSubjectFields(pk.getSigningCertificate())); System.out.println("Document modified: "
 * + !pk.verify()); Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall, null, cal); if (fails ==
 * null) System.out.println("Certificates verified against the KeyStore"); else
 * System.out.println("Certificate failed: " + fails[1]); }
 * 
 * 
 * @author paul
 * 
 */

public class PDFSignatureVerifier
{
    public static void main(String[] args)
    {

    }
}

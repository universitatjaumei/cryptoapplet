//package es.uji.dsign.crypto.test;
//
//import java.io.ByteArrayInputStream;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.InputStream;
//import java.math.BigInteger;
//import java.security.KeyStore;
//import java.security.Security;
//import java.security.cert.X509Certificate;
//import java.util.Enumeration;
//
//import org.apache.commons.httpclient.HttpClient;
//import org.apache.commons.httpclient.methods.PostMethod;
//import org.bouncycastle.cms.SignerId;
//import org.bouncycastle.tsp.TSPAlgorithms;
//import org.bouncycastle.tsp.TimeStampRequest;
//import org.bouncycastle.tsp.TimeStampRequestGenerator;
//import org.bouncycastle.tsp.TimeStampResponse;
//import org.bouncycastle.tsp.TimeStampToken;
//
//public class TimeStampGeneration
//{
//	public static void main(String[] args) throws Exception
//	{
//		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//
//		PostMethod post = new PostMethod("http://tss.pki.gva.es:8318/tsa");
//
//		TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
//
//		// Request TSA to return certificate
//		reqGen.setCertReq(false);
//
//		// Make a TSP request this is a dummy sha1 hash (20 zero bytes) and
//		// nonce=100
//		TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
//
//		byte[] enc_req = request.getEncoded();
//		ByteArrayInputStream bais = new ByteArrayInputStream(enc_req);
//
//		post.setRequestBody(bais);
//		post.setRequestContentLength(enc_req.length);
//		post.setRequestHeader("Content-type", "application/timestamp-query");
//
//		HttpClient http_client = new HttpClient();
//		http_client.executeMethod(post);
//		InputStream in = post.getResponseBodyAsStream();
//
//		// Read TSP response
//		TimeStampResponse resp = new TimeStampResponse(in);
//		resp.validate(request);
//		System.out.println("Timestamp validated");
//
//		TimeStampToken tsToken = resp.getTimeStampToken();
//		FileOutputStream fos = new FileOutputStream("/tmp/token.data");
//		fos.write(tsToken.getEncoded());
//		fos.flush();
//		fos.close();
//
//		SignerId signer_id = tsToken.getSID();
//
//		BigInteger cert_serial_number = signer_id.getSerialNumber();
//
//		System.out.println("Signer ID serial " + signer_id.getSerialNumber());
//		System.out.println("Signer ID issuer " + signer_id.getIssuerAsString());
//		System.out.println("Signer ID cert   " + signer_id.getCertificate());
//
//		KeyStore mks = KeyStore.getInstance("JKS");
//		mks.load(new FileInputStream("keystore"), "pwd".toCharArray());
//
//		X509Certificate cert = null;
//
//		for (Enumeration en = mks.aliases() ; en.hasMoreElements() ; )
//		{
//			String alias = (String) en.nextElement();
//			cert = (X509Certificate) mks.getCertificate(alias);
//
//			if (cert.getSerialNumber().equals(cert_serial_number))
//			{
//				System.out.println ("using certificate with serial: " + cert.getSerialNumber());
//			}
//
//			System.out.println("Certificate subject dn " + cert.getSubjectDN());
//			System.out.println("Certificate serial " + cert.getSerialNumber());
//
//			try
//			{
//				tsToken.validate(cert, "BC");
//				System.out.println("TS info " + tsToken.getTimeStampInfo().getGenTime());
//				System.out.println("TS info " + tsToken.getTimeStampInfo());
//				System.out.println("TS info " + tsToken.getTimeStampInfo().getAccuracy());
//				System.out.println("TS info " + tsToken.getTimeStampInfo().getNonce());
//			}
//			catch (Exception e)
//			{
//				System.out.println("No se puede verificar el timestamp con este certificado: " + e.getLocalizedMessage());
//			}
//		}
//	}
//}

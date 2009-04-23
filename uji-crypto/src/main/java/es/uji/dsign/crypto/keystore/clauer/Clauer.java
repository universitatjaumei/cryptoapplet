package es.uji.dsign.crypto.keystore.clauer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
//import java.io.DataOutputStream;
//import java.io.InputStream;
//import java.io.OutputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
//import java.net.Socket;
import java.util.Vector;
import java.util.Enumeration;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
//import java.security.KeyFactory;
//import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyPair;

//import org.bouncycastle.asn1.ASN1InputStream;

//import es.uji.util.Base64;

import org.bouncycastle.util.encoders.HexEncoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;

import es.uji.dsign.crypto.keystore.clauer.ClauerRunTime;

public class Clauer
{
	private ClauerRunTime clRunTime = new ClauerRunTime();
	private ClauerHandle clHandle = new ClauerHandle();

	public byte TYPE_PEM_PRIVATE_KEY = 1;
	public byte TYPE_OWN_CERTIFICATE = 2;

	private boolean _initialized = false;
	private boolean _isAuth = false;
	private boolean _cached = false;

	private Vector<String> aliases = new Vector<String>();
	private Vector<Certificate> certs = new Vector<Certificate>();

	public Clauer()
	{
		// Install BC Provider
		if (Security.getProvider("BC") == null)
		{
			BouncyCastleProvider bcp = new BouncyCastleProvider();
			Security.addProvider(bcp);
		}
	}

	public void open(String device) throws IOException, Exception
	{
		String[] devs = clRunTime.enumerateDevices();
		boolean ok = false;

		for (int i = 0; i < devs.length; i++)
		{
			if (device.equals(devs[i]))
			{
				ok = true;
			}
		}

		if (!ok)
		{
			throw new Exception("InvalidDeviceName:" + device);
		}

		clRunTime.startSession(device, "", clHandle);
		_isAuth = false;
		_initialized = true;
	}

	public boolean openAuth(String device, String password) throws IOException, Exception
	{
		String[] devs = clRunTime.enumerateDevices();
		boolean ok = false;

		for (int i = 0; i < devs.length; i++)
		{
			if (device.equals(devs[i]))
			{
				ok = true;
			}
		}

		if (!ok)
		{
			throw new Exception("InvalidDeviceName:" + device);
		}

		if (password!=null && !password.equals("") && clRunTime.startSession(device, password, clHandle))
		{
			_isAuth = true;
			_initialized = true;
			return true;
		}

		return false;
	}

	public boolean isAuthSession()
	{
		return _isAuth;
	}

	public boolean close() throws IOException
	{
		clRunTime.closeSession();
		_initialized = false;
		_isAuth = false;
		return true;
	}

	public String[] getCertificateAliases() throws Exception
	{
		if (!_initialized)
		{
			throw new Exception("UninitializedClauer");
		}

		byte[][] blocks = clRunTime.readAllTypeObjects(this.TYPE_OWN_CERTIFICATE);
		String[] sRes = new String[blocks.length];
		HexEncoder hex = new HexEncoder();

		aliases.clear();
		certs.clear();
		
		for (int i = 0; i < blocks.length; i++)
		{
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = null;

			ByteArrayOutputStream bOs = new ByteArrayOutputStream();
			hex.encode(blocks[i], 8 + 4 + 31, 20, bOs);
			sRes[i] = bOs.toString();
			
			aliases.add(sRes[i]);

			ByteArrayInputStream certIs = new ByteArrayInputStream(blocks[i]);
			DataInputStream dis = new DataInputStream(certIs);

			/* Take out the header */
			dis.readInt();
			dis.readInt();

			int tam = Integer.reverseBytes(dis.readInt());

			/* Take out irrelevant info */
			for (int j = 0; j < 51; j++)
			{
				dis.read();
			}

			/* Read certificate information */
			byte[] bCert = new byte[tam];
			dis.read(bCert, 0, tam);

			ByteArrayInputStream certAuxIs = new ByteArrayInputStream(bCert);
			cert = (X509Certificate) cf.generateCertificate(certAuxIs);
			certs.add(cert);
		}
		_cached = true;

		return sRes;
	}

	public Certificate getCertificate(String alias) throws CertificateException, Exception
	{
		int i = 0;

		if (!_cached)
		{
			getCertificateAliases();
		}

		for (Enumeration e = aliases.elements(); e.hasMoreElements(); i++)
		{
			if (alias.equals(e.nextElement()))
			{
				return certs.get(i);
			}
		}
		return null;
	}

	public PrivateKey getPrivateKey(String alias) throws Exception
	{

		HexEncoder hex = new HexEncoder();
		// Base64 b64= new Base64();

		if (!_initialized || !_isAuth)
		{
			throw new Exception("UninitializedClauerOrUnauthenticated");
		}

		byte[] block = new byte[10240];

		int nblock = clRunTime.readFirstTypeBlock(this.TYPE_PEM_PRIVATE_KEY, block);

		// System.out.println("alias = " + alias);
		while (nblock != -1)
		{
			ByteArrayOutputStream bOs = new ByteArrayOutputStream();
			hex.encode(block, 8 + 4 + 1, 20, bOs);
			String id = bOs.toString();

			if (id.equals(alias))
			{
				ByteArrayInputStream keyIs = new ByteArrayInputStream(block);
				DataInputStream dis = new DataInputStream(keyIs);

				/* Take out the header */
				dis.readInt();
				dis.readInt();
				dis.read();

				int tam = Integer.reverseBytes(dis.readInt());

				/* Take out irrelevant info */
				for (int i = 0; i < 20; i++)
				{
					dis.read();
				}

				/* Read certificate information */
				byte[] bkey = new byte[tam];

				dis.read(bkey, 0, tam);

				// KeyFactory rSAKeyFactory = KeyFactory.getInstance("RSA");
				// String bk= new String(bkey);
				// System.out.println("KEY: " + bk );

				Reader fRd = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bkey)));
				PEMReader pemRd = new PEMReader(fRd, null);
				Object o;
				o = pemRd.readObject();

				if (o instanceof KeyPair)
				{
					KeyPair pair = (KeyPair) o;
					// System.out.println(pair.getPublic());
					PrivateKey p = pair.getPrivate();
					return p;
				}
			}
			nblock = clRunTime.readNextTypeBlock(this.TYPE_PEM_PRIVATE_KEY, block, nblock);
		}
		
		return null;
	}
}

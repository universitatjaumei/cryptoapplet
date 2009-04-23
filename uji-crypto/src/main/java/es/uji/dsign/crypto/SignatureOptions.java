package es.uji.dsign.crypto;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public class SignatureOptions {

	private boolean _isByteArray= false;
	private boolean _isLocalFile= false;
	private X509Certificate certificate= null; 
	private PrivateKey privateKey= null; 
	private Provider provider=null; 
	byte[] toSign= null;

	public SignatureOptions(){
		
	}	 

	public boolean is_byteArray() {
		return _isByteArray;
	}

	public void set_isbyteArray(boolean isByteArray) {
		_isByteArray = isByteArray;
	}

	public boolean is_localFile() {
		return _isLocalFile;
	}

	public void set_localFile(boolean isLocalfile) {
		_isLocalFile = isLocalfile;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public Provider getProvider() {
		return provider;
	}

	public void setProvider(Provider provider) {
		this.provider = provider;
	}
	
	public byte[] getToSignByteArray(){
		return this.toSign;
	}
	
	public void setToSignByteArray(byte[] b){
		this.toSign= b;
	}
}

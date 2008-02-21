/*
 * EncryptedStreamSAXParser.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for parsing encrypted
 * data from streams. Designed to parse large encrypted
 * files. Uses PKCS#11 driver to decrypt the transport key.
 * This implementation uses SAX parser.
 * AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */
package es.uji.dsign.crypto.digidoc.xmlenc.factory;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.util.zip.Inflater;
import java.util.Stack;
import java.security.cert.X509Certificate;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import es.uji.dsign.crypto.digidoc.Base64Util;
import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.factory.SAXDigiDocException;
import es.uji.dsign.crypto.digidoc.factory.SignatureFactory;
import es.uji.dsign.crypto.digidoc.utils.ConfigManager;
import es.uji.dsign.crypto.digidoc.xmlenc.EncryptedData;
import es.uji.dsign.crypto.digidoc.xmlenc.EncryptedKey;
import es.uji.dsign.crypto.digidoc.xmlenc.EncryptionProperty;

import org.xml.sax.SAXException;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;



import org.apache.log4j.Logger;

/**
 * Implementation class for reading and writing
 * encrypted files using a SAX parser
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class EncryptedStreamSAXParser 
	extends DefaultHandler
	implements EncryptedStreamParser 
{
	private Stack m_tags;
	private EncryptedData m_doc;
	private StringBuffer m_sbCollectChars;
	/** log4j logger */
	private Logger m_logger = null;
	private int m_totalDecrypted, m_totalDecompressed, m_totalInput;
	/** stream to write decrypted data */
	private OutputStream m_outStream;
	/** value of Recipient atribute to select the <EncryptedKey> */
	private String m_recvName;
	/** pin code used to decrypt the transport key */
	private String m_pin;
	/** index of PKCS#11 token used in decryption */
	private int m_token;
	/** cipher used in decryption of data */
	private Cipher m_cipher;
	/** flag: decrypting / not decrypting */
	private boolean m_bDecrypting;
	private String m_leftB64;
	/** decompressor */
	private Inflater m_decompressor;
	/** we use this two buffer system because xml parser returns parsed base64 data in 
	 * various size of chunks and we know that this is the last chunk only after we
	 * have met the </CipherValue> tag but the row before that might also be shorter
	 * and thus require us to use cipher.doFinal() instead of cpher.update(). So we
	 * constantly store away the newest buffer and work on the previous one. This
	 * way we know that it's the last buffer when working on the last row.
	 */
	private String m_parseBuf1;
	private String m_parseBuf2;
	private SecretKey m_transportKey;
	private int m_nBlockType;
	private static int DENC_BLOCK_FIRST = 1;
	private static int DENC_BLOCK_MIDDLE = 2;
	private static int DENC_BLOCK_LAST = 3;
	
	
	/**
	 * Creates new EncryptedStreamSAXParser
	 * and initializes the variables
	 */
	public EncryptedStreamSAXParser() {
			m_tags = new Stack();
			m_doc = null;
			m_pin = null;
			m_cipher = null;
			m_outStream = null;
			m_recvName = null;
			m_leftB64 = null;
			m_bDecrypting = false;
			m_totalDecrypted = 0;
			m_totalDecompressed = 0;
			m_totalInput = 0;
			m_token = 0;
			m_sbCollectChars = null;
			m_decompressor = null;
			m_parseBuf1 = null;
			m_parseBuf2 = null;
			m_transportKey = null;
			m_logger = Logger.getLogger(EncryptedStreamSAXParser.class);
	}
		
	/**
	 * initializes the implementation class
	 * @see es.uji.dsign.crypto.digidoc.xmlenc.factory.EncryptedDataParser#init()
	 */
	public void init() throws DigiDocException {

	}
	
	/**
	 * Initializes the Recipient atribute value
	 * used for locating the right <EncryptedKey>
	 * to be used for deryption
	 * @param s value of Recipient atribute
	 */
	public void setRecipientName(String s)
	{
		m_recvName = s;
	}
	
	/**
	 * Initializes the output stream where to write
	 * decrypted data
	 * @param outs output stream already opened by the user
	 */
	public void setOutputStream(OutputStream outs)
	{
		m_outStream = outs;
	}
	
	/**
	 * Initializes the PIN code used to decrypt the transport key
	 * @param pin PIN code
	 */
	public void setPin(String pin) {
		m_pin = pin;
	}

	/** 
	 * Initializes the PKCS#11 token index used for decryption
	 * @param tok PKCS#11 token index used for decryption
	 */
	public void setToken(int tok)
	{
		m_token = tok;
	}
	
	/**
	 * Reads in a EncryptedData file (.cdoc)
	 * @param dencStream opened stream with EncrypyedData data
	 * The user must open and close it. 
	 * @param outs output stream for decrypted data
	 * @param token index of PKCS#11 token used
	 * @param pin pin code to decrypt transport key using PKCS#11
	 * @param recipientName Recipient atribute value of <EncryptedKey>
	 * used to locate the correct transport key to decrypt with
	 * @return number of bytes successfully decrypted
	 * @throws DigiDocException for decryption errors
	 */
	public int decryptStreamUsingRecipientName(InputStream dencStream, 
			OutputStream outs, int token, String pin, String recipientName) 
		throws DigiDocException
	{
		// Use an instance of ourselves as the SAX event handler
		EncryptedStreamSAXParser handler = this;
		handler.setRecipientName(recipientName);
		handler.setOutputStream(outs);
		handler.setPin(pin);
		handler.setToken(token);
		// Use the default (non-validating) parser
		SAXParserFactory factory = SAXParserFactory.newInstance();
		//factory.setNamespaceAware(true);
		try {
			SAXParser saxParser = factory.newSAXParser();
			saxParser.parse(dencStream, handler);
		} catch (SAXDigiDocException ex) {
			throw ex.getDigiDocException();
		} catch (Exception ex) {
			DigiDocException.handleException(ex,
				DigiDocException.ERR_PARSE_XML);
		}
		if (m_doc == null)
			throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
				"This document is not in EncryptedData format", null);		
		return m_totalDecrypted;
	}


	/**
	 * Start Document handler
	 */
	public void startDocument() throws SAXException {
		m_doc = null;
		m_sbCollectChars = null;
		m_decompressor = null;
		m_parseBuf1 = null;
		m_parseBuf2 = null;
		m_totalDecrypted = 0;
		m_totalDecompressed = 0;
		m_totalInput = 0;
		m_transportKey = null;
		m_cipher = null;
		m_nBlockType = DENC_BLOCK_FIRST;
	}

	/**
	 * End Document handler
	 */
	public void endDocument() throws SAXException {
	}
	
	/**
	 * Finds the value of an atribute by name
	 * @param atts atributes
	 * @param attName name of atribute
	 * @return value of the atribute
	 */
	private String findAtributeValue(Attributes attrs, String attName) {
		String value = null;
		for (int i = 0; i < attrs.getLength(); i++) {
			String key = attrs.getQName(i);
			if (key.equals(attName) || key.indexOf(attName) != -1) {
				value = attrs.getValue(i);
				break;
			}
		}
		return value;
	}
	
	/**
	 * Checks if this document is in <EncryptedData> format
	 * @throws SAXDigiDocException if the document is not in <EncryptedData> format
	 */
	private void checkEncryptedData()
		throws SAXDigiDocException
	{
		if(m_doc == null)
			throw new SAXDigiDocException(DigiDocException.ERR_XMLENC_NO_ENCRYPTED_DATA, 
				"This document is not in EncryptedData format!");
	}
	
	/**
	 * Checks if the <EncryptedKey> objects exists
	 * @throws SAXDigiDocException if the objects <EncryptedKey> does not exist
	 */
	private void checkEncryptedKey(EncryptedKey key)
		throws SAXDigiDocException
	{
		if(key == null)
			throw new SAXDigiDocException(DigiDocException.ERR_XMLENC_NO_ENCRYPTED_KEY, 
				"This <EncryptedKey> object does not exist!");
	}

	/**
	 * Start Element handler
	 * @param namespaceURI namespace URI
	 * @param lName local name
	 * @param qName qualified name
	 * @param attrs attributes
	 */
	public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
		throws SAXDigiDocException 
	{
		String tName = qName;
		if(tName.indexOf(":") != -1)
			tName = qName.substring(qName.indexOf(":")+1);
		if (m_logger.isDebugEnabled())
			m_logger.debug("Start Element: "	+ tName + " qname: " + qName + " lname: "  + lName + " uri: " + namespaceURI);
		m_tags.push(tName);
		if (tName.equals("KeyName") ||
			tName.equals("CarriedKeyName") ||
			tName.equals("X509Certificate") ||
			tName.equals("EncryptionProperty") )
			m_sbCollectChars = new StringBuffer();
		if(tName.equals("CipherValue")) {
			if(m_tags.search("EncryptedKey") != -1) { // child of <EncryptedKey>
				m_sbCollectChars = new StringBuffer();
			} else { // child of <EncryptedKey>
				m_sbCollectChars = null;
				m_bDecrypting = true;
			}
		}
		// <EncryptedData>
		if(tName.equals("EncryptedData")) {
		    String str = findAtributeValue(attrs, "xmlns");
		    try {
		    	m_doc = new EncryptedData(str);
		    	str = findAtributeValue(attrs, "Id");
		    	if(str != null)
		    		m_doc.setId(str);
				str = findAtributeValue(attrs, "Type");
				if(str != null)
					m_doc.setType(str);
				str = findAtributeValue(attrs, "MimeType");
				if(str != null)
					m_doc.setMimeType(str);		 
				if(m_doc.getMimeType() != null && m_doc.getMimeType().equals(EncryptedData.DENC_ENCDATA_MIME_ZLIB)) {
					m_decompressor = new Inflater();
				}
			} catch (DigiDocException ex) {
				SAXDigiDocException.handleException(ex);
			}
		}
		// <EncryptionMethod>
		if(tName.equals("EncryptionMethod")) {
			checkEncryptedData();
			if (m_tags.search("EncryptedKey") != -1) { // child of <EncryptedKey>
				EncryptedKey ekey = m_doc.getLastEncryptedKey();
				checkEncryptedKey(ekey);
				try {
					ekey.setEncryptionMethod(findAtributeValue(attrs, "Algorithm"));
				} catch (DigiDocException ex) {
					SAXDigiDocException.handleException(ex);
				}
			} else { // child of <EncryptedData>
				try {
					m_doc.setEncryptionMethod(findAtributeValue(attrs, "Algorithm"));
				} catch (DigiDocException ex) {
					SAXDigiDocException.handleException(ex);
				}				
			}
		}
		// <EncryptedKey>
		if(tName.equals("EncryptedKey")) {
			checkEncryptedData();
			EncryptedKey ekey = new EncryptedKey();
			m_doc.addEncryptedKey(ekey);
			String str = findAtributeValue(attrs, "Recipient");
			if(str != null)
				ekey.setRecipient(str);
			str = findAtributeValue(attrs, "Id");
			if(str != null)
				ekey.setId(str);
		}
		// <EncryptionProperties>
		if(tName.equals("EncryptionProperties")) {
			checkEncryptedData();
			String str =findAtributeValue(attrs, "Id");
			if(str != null)
				m_doc.setEncryptionPropertiesId(str);
		}
		// <EncryptionProperty>
		if(tName.equals("EncryptionProperty")) {
			checkEncryptedData();
			EncryptionProperty eprop = new EncryptionProperty();
			m_doc.addProperty(eprop);
			String str =findAtributeValue(attrs, "Id");
			if(str != null)
				eprop.setId(str);
			str =findAtributeValue(attrs, "Target");
			if(str != null)
				eprop.setTarget(str);
			str =findAtributeValue(attrs, "Name");
			try {
				if(str != null)
					eprop.setName(str);
			} catch (DigiDocException ex) {
				SAXDigiDocException.handleException(ex);
			}
		}
	}
	
	/**
	 * End Element handler
	 * @param namespaceURI namespace URI
	 * @param lName local name
	 * @param qName qualified name
	 */
	public void endElement(String namespaceURI, String sName, String qName)
		throws SAXException 
	{
		String tName = qName;
		if(tName.indexOf(":") != -1)
			tName = qName.substring(tName.indexOf(":")+1);
		if(m_logger.isDebugEnabled())
		 	m_logger.debug("End Element: " + tName);
		// remove last tag from stack
		String currTag = (String) m_tags.pop();
		//	<KeyName>
		if(tName.equals("KeyName")) {
			checkEncryptedData();
			EncryptedKey ekey = m_doc.getLastEncryptedKey();
			checkEncryptedKey(ekey);
			ekey.setKeyName(m_sbCollectChars.toString());
			m_sbCollectChars = null; // stop collecting
		}
		//	<CarriedKeyName>
		if(tName.equals("CarriedKeyName")) {
			checkEncryptedData();
			EncryptedKey ekey = m_doc.getLastEncryptedKey();
			checkEncryptedKey(ekey);
			ekey.setCarriedKeyName(m_sbCollectChars.toString());
			m_sbCollectChars = null; // stop collecting
		}
		//	<X509Certificate>
		if(tName.equals("X509Certificate")) {
			checkEncryptedData();
			EncryptedKey ekey = m_doc.getLastEncryptedKey();
			checkEncryptedKey(ekey);
			try {
				X509Certificate cert = SignedDoc.readCertificate(Base64Util.
					decode(m_sbCollectChars.toString().getBytes()));
				ekey.setRecipientsCertificate(cert);
			} catch (DigiDocException ex) {
				SAXDigiDocException.handleException(ex);
			}
			m_sbCollectChars = null; // stop collecting
		}
		//	<CipherValue>
		if(tName.equals("CipherValue")) {
			checkEncryptedData();
			if (m_tags.search("EncryptedKey") != -1) { // child of <EncryptedKey>
				EncryptedKey ekey = m_doc.getLastEncryptedKey();
				checkEncryptedKey(ekey);
				ekey.setTransportKeyData(Base64Util.
					decode(m_sbCollectChars.toString().getBytes()));
				// decrypt transport key if possible
				if(m_recvName != null && ekey.getRecipient() != null &&
					ekey.getRecipient().equals(m_recvName)) {
					// decrypt transport key
					try {
						SignatureFactory sfac = ConfigManager.instance().getSignatureFactory();
						if(m_logger.isDebugEnabled())
							m_logger.debug("Decrypting key: " + m_recvName + " with token: " + m_token); 
						byte [] decdata = sfac.decrypt(ekey.getTransportKeyData(), m_token, m_pin);
						m_transportKey = (SecretKey) new SecretKeySpec(decdata, 
								ConfigManager.instance().getProperty("DIGIDOC_ENCRYPTION_ALOGORITHM"));
						if(m_logger.isDebugEnabled())
							m_logger.debug("Transport key: " + ((m_transportKey == null) ? "ERROR" : "OK") + " len: " + decdata.length);
					} catch(DigiDocException ex) {
						SAXDigiDocException.handleException(ex);
					}
				}
			} else { // child of <EncryptedData>
				m_bDecrypting = false;
				decryptBlock(null, DENC_BLOCK_LAST);
				if(m_logger.isInfoEnabled())
					m_logger.info("Total input: " + m_totalInput + " decrypted: " + m_totalDecrypted + " decompressed: " + m_totalDecompressed);
			}
			m_sbCollectChars = null; // stop collecting
		}
		// <EncryptionProperty>
		if(tName.equals("EncryptionProperty")) {
			checkEncryptedData();
			EncryptionProperty eprop = m_doc.getLastProperty();
			try {
				eprop.setContent(m_sbCollectChars.toString());
			} catch (DigiDocException ex) {
				SAXDigiDocException.handleException(ex);
			}
			m_sbCollectChars = null; // stop collecting
		}
		
	}
	
	/**
	 * Called with a block of base64 data that
	 * must be decoded, decrypted and possibly also 
	 * decompressed
	 * @param data base64 encoded input data
	 * @param nBlockType type of block (first, middle, last)
	 * @throws SAXException
	 */
	private void decryptBlock(String data, int nBlockType)
	throws SAXException
	{		
		// move the input buffers in the FIFO queue
		// store the newest in the queue and use the 
		// last one instead to have some buffer left
		// when we reach the end-tag since then we
		// have to pass this data to doFinal()
		m_parseBuf2 = m_parseBuf1;
		m_parseBuf1 = data;
		String indata = m_parseBuf2;
		if(m_logger.isDebugEnabled())
		 	m_logger.debug("IN " + ((data != null) ? data.length() : 0) +
		 			" input: " + ((indata != null) ? indata.length() : 0) + 
					" left: " + ((m_leftB64 != null) ? m_leftB64.length() : 0) + 
					" block-type: " + nBlockType);
		try {
			// get the cipher if first block of data
			if(nBlockType == DENC_BLOCK_FIRST) {
				byte [] decdat = Base64Util.decode(data);
				byte [] iv = new byte[16];
				if(decdat != null && decdat.length > 16) {
					System.arraycopy(decdat, 0, iv, 0, 16);
					StringBuffer ivlog = new StringBuffer("USING IV:");
					for(int i = 0; i < 16; i++)
						ivlog.append(" " + iv[i]);
					if(m_logger.isDebugEnabled())
					 	m_logger.debug(ivlog.toString());
				}
				m_cipher = m_doc.getCipher(Cipher.DECRYPT_MODE, m_transportKey, iv);
				if(m_logger.isDebugEnabled())
					m_logger.debug("Decrypt ciper: " + ((m_cipher == null) ? "ERROR" : "OK"));
			}
		} catch(DigiDocException ex) {
			DigiDocException de = new DigiDocException(DigiDocException.ERR_XMLENC_DECRYPT, 
					"Error constructing cipher: " + ex, ex);
			SAXDigiDocException.handleException(de);
		}
		if(indata == null)
			return; // nothing to do
		try {
			// decode base64
			ByteArrayOutputStream bos = new ByteArrayOutputStream(); 
			StringBuffer b64data = new StringBuffer();
			if(m_leftB64 != null) 
				b64data.append(m_leftB64);
			if(indata != null) {
				b64data.append(indata);
				m_totalInput += indata.length();
			}
			int nUsed = 0;
			if(m_leftB64 != null || indata != null)
				nUsed = Base64Util.decodeBlock(b64data.toString(), bos, nBlockType == DENC_BLOCK_LAST);
			// copy the leftover for next run
			if(indata != null && nUsed < indata.length())
				m_leftB64 = b64data.substring(nUsed);
			else
				m_leftB64 = null;
			// decrypt the data
			byte[] encdata = null;
			if(m_leftB64 != null || indata != null)
				encdata = bos.toByteArray();
			bos = null;
			
			byte[] decdata = null;
			if(m_logger.isDebugEnabled())
				m_logger.debug("Decoding: " + b64data.length() + " got: " + 
						((encdata != null) ? encdata.length : 0) +  " last: " + (nBlockType == DENC_BLOCK_LAST));
			/*if(nBlockType == DENC_BLOCK_LAST) {
				if(encdata != null && encdata.length > 0) {
					// check for extra (base64?) padding with 0xF bytes
					int nExtPad = 0, n = 0;
					do {
						n = new Integer(encdata[encdata.length - 1 - nExtPad]).intValue();
						if(m_logger.isDebugEnabled())
							m_logger.debug("Data at: " + (encdata.length - 1 - nExtPad) + " = " + n);
						if(n == 16)
							nExtPad++;
					} while(n == 16 && nExtPad < encdata.length - 1);
					if(nExtPad > 0) {
						if(m_logger.isDebugEnabled())
							m_logger.debug("Removing extra padding: " + nExtPad + " from: " + encdata.length);
						byte [] tmp = new byte[encdata.length - nExtPad];
						System.arraycopy(encdata, 0, tmp, 0, encdata.length - nExtPad);
						encdata = tmp;
					}
					decdata = m_cipher.doFinal(encdata);
				}
				//else decdata = m_cipher.doFinal();
			} else */
				/*if(m_totalDecrypted == 0)
					decdata = m_cipher.update(encdata, 16, encdata.length - 16);
				else*/
					decdata = m_cipher.update(encdata);
			
			
			if(m_logger.isDebugEnabled())
			 	m_logger.debug("Decrypted input: " + ((indata != null) ? indata.length() : 0) + " decoded: " + 
			 			((encdata != null) ? encdata.length : 0) +
			 			" decrypted: " + ((decdata != null) ? decdata.length : 0) );
			// remove padding on the last block
			if(decdata != null && encdata != null && nBlockType == DENC_BLOCK_LAST) {
				int nPadLen = new Integer(decdata[decdata.length-1]).intValue();
				int nExtPad = 0;
				if(nPadLen > 0) {
				while(nPadLen == 16 && decdata.length > (nExtPad+1)) {
					nExtPad ++;
					nPadLen = new Integer(decdata[decdata.length - 1 - nExtPad]).intValue();					
				}
				if(m_logger.isDebugEnabled())
					m_logger.debug("Decrypted: " + decdata.length + " encoded: " + encdata.length + " check padding: " + nPadLen + " ext: " + nExtPad);
				boolean bPadOk = true;
				if(nPadLen > 16 || nPadLen < 0)
					bPadOk = false;
				for(int i = decdata.length - nPadLen - nExtPad; bPadOk && nPadLen < decdata.length && i < decdata.length - 1 - nExtPad; i++) {
					if(m_logger.isDebugEnabled())
						m_logger.debug("Data at: " + i + " = " + decdata[i]);
					if(decdata[i] != 0) {
						if(m_logger.isDebugEnabled())
							m_logger.debug("Data at: " + i + " = " + decdata[i] + " cancel padding");
						bPadOk = false;
						//break;
					}
				}
				if(bPadOk && nExtPad >= 0 && nPadLen >= 0) {
					if(m_logger.isInfoEnabled())
						m_logger.info("Removing padding: " + (nPadLen+nExtPad) + " bytes");
					byte[] data2 = new byte[decdata.length - nPadLen - nExtPad];
					System.arraycopy(decdata, 0, data2, 0, decdata.length - nPadLen - nExtPad);
					decdata = data2;
				}	
				}
			}
			// decompress if necessary and write to output stream
			if(decdata != null) {
				// check compression
				if(m_decompressor != null) {
					if(m_totalDecrypted > 0)
						m_decompressor.setInput(decdata);
					else
						m_decompressor.setInput(decdata, 16, decdata.length - 16);
					byte [] m_decbuf = new byte[1024*8];
					int nDecomp = m_decompressor.inflate(m_decbuf);
					if(m_logger.isDebugEnabled())
						m_logger.debug("Decompressing: " + decdata.length + " into: " + m_decbuf.length + " got: " + nDecomp);
					
					if(nDecomp > 0) {
						m_outStream.write(m_decbuf, 0, nDecomp);
						m_totalDecompressed += nDecomp;
					}
				}
				else {
					if(m_totalDecrypted > 0)
						m_outStream.write(decdata);
					else 
						m_outStream.write(decdata, 16, decdata.length - 16);
				}
				m_totalDecrypted += decdata.length;
			}
		} catch(Exception ex) {
			DigiDocException de = new DigiDocException(DigiDocException.ERR_XMLENC_DECRYPT, 
					"Error decrypting: " + ex, ex);
			SAXDigiDocException.handleException(de);
		}
	}
	
	/**
	 * SAX characters event handler
	 * @param buf received bytes array
	 * @param offset offset to the array
	 * @param len length of data
	 */
	public void characters(char buf[], int offset, int len)
		throws SAXException {
		String s = new String(buf, offset, len);
		//System.out.println("Chars: " + s);
		// just collect the data since it could
		// be on many lines and be processed in many events
		if (s != null) {		
			if (m_sbCollectChars != null)
				m_sbCollectChars.append(s);
			if(m_bDecrypting) {
				decryptBlock(s, m_nBlockType);
				if(m_nBlockType == DENC_BLOCK_FIRST)
					m_nBlockType = DENC_BLOCK_MIDDLE;
			}
		}
	}
		
}

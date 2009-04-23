/*
 * jdigidoc.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Generic test programm for JDigiDoc library. 
 * Provides a command-line interface to most features of the library.
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

package es.uji.dsign.crypto.test.digidoc;
import es.uji.dsign.crypto.digidoc.factory.DigiDocFactory;
import es.uji.dsign.crypto.digidoc.factory.NotaryFactory;
import es.uji.dsign.crypto.digidoc.factory.SignatureFactory;
import es.uji.dsign.crypto.digidoc.xmlenc.factory.EncryptedDataParser;
import es.uji.dsign.crypto.digidoc.xmlenc.factory.EncryptedStreamParser;
import es.uji.dsign.crypto.digidoc.*;
import es.uji.dsign.crypto.digidoc.utils.*;
import es.uji.dsign.crypto.digidoc.xmlenc.*;


import java.io.*;
import java.util.*;
import java.security.cert.X509Certificate;



/**
 * jdigidoc is a small command-line programm providing
 * an interface to most of the librarys functionality and 
 * also documenting the library and serving as sample
 * code for other developers.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class jdigidoc {
	/** signed doc object if used */
	private SignedDoc m_sdoc;
	/** encrypted data object if used */
	private EncryptedData m_cdoc;
	
	/**
	 * Constructor for jdigidoc
	 */
	public jdigidoc()
	{
		m_sdoc = null;
		m_cdoc = null;
	}

	/**
	 * Checks for commands related to
	 * creating signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runNewSignedDocCmds(String[] args)
	{
		boolean bFound = false, bOk = true;
		String format = SignedDoc.FORMAT_DIGIDOC_XML;
		String version = SignedDoc.VERSION_1_3;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-new")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					format = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					version = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			try {
				System.out.println("Creating digidoc: " + format + ", " + version);
				m_sdoc = new SignedDoc(format, version);
			} catch(Exception ex) {
				bOk = false;
				System.err.println("Error creating digidoc format: " + format + " version: " + version + " - " + ex);
				ex.printStackTrace(System.err);
			}
		}			
		return bOk; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * writing signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runWriteSignedDocCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String outFile = null;
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-out")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				} else {
					bOk = false;
					System.err.println("Missing output file of -ddoc-out command");
				}
			}
		}
		if(bFound && outFile != null) {
			try {
				if(m_sdoc == null) {
					System.err.println("No signed document to sign. Use -ddoc-in or -ddoc-new commands!");
					return false;
				}
				System.out.println("Writing digidoc in file: " + outFile);
				m_sdoc.writeToFile(new File(outFile));  
			} catch(Exception ex) {
				bOk = false;
				System.err.println("Error writing digidoc: " + ex);
				ex.printStackTrace(System.err);
			}
		}
		return bOk; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * signing signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runSignSignedDocCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-sign")) {
				String pin = null;
				String manifest = null;
				String country = null;
				String city = null;
				String state = null;
				String zip = null;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					manifest = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					country = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					state = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					city = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					zip = args[i+1];
					i++;
				}				
				if(pin != null) {
					try {
						if(m_sdoc == null) {
							System.err.println("No signed document to sign. Use -ddoc-in or -ddoc-new commands!");
							return false;
						}
						// manifest
						String[] roles = null;
						if(manifest != null) {
							roles = new String[1];
							roles[0] = manifest;
						}
						// address
						SignatureProductionPlace adr = null;
						if(country != null || state != null || city != null || zip != null)
							adr = new SignatureProductionPlace(city, state, country, zip);
						System.out.println("Signing digidoc");
						SignatureFactory sigFac = ConfigManager.
										instance().getSignatureFactory();
						System.out.println("GET Cert");
						X509Certificate cert = sigFac.getCertificate(0, pin);
						System.out.println("Prepare signature");
						Signature sig = m_sdoc.prepareSignature(cert, roles, adr);
						byte[] sidigest = sig.calculateSignedInfoDigest();
            
						byte[] sigval = sigFac.sign(sidigest, 0, pin);
						System.out.println("Finalize signature");
						sig.setSignatureValue(sigval);
             
						// get confirmation
						System.out.println("Get confirmation");
						sig.getConfirmation();
						System.out.println("Confirmation OK!");
            
            		
					} catch(Exception ex) {
						bOk = false;
						System.err.println("Error adding DataFile: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing pin of -ddoc-sign command");
				}
			}
		}
		return bOk; // nothing to do?
	}


	/**
	 * Checks for commands related to
	 * adding data files to signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runAddSignedDocCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-add")) {
				String inFile = null;
				String inMime = null;
				String inContent = DataFile.CONTENT_EMBEDDED_BASE64;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inMime = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inContent = args[i+1];
					i++;
				}
				if(inFile != null && inMime != null) {
					try {
						if(m_sdoc == null) {
							System.out.println("Creating digidoc: " + SignedDoc.FORMAT_DIGIDOC_XML + ", " + SignedDoc.VERSION_1_3);
							m_sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
						}
						System.out.println("Adding data-file: " + inFile + ", " + inMime + ", " + inContent);
						DataFile df = m_sdoc.addDataFile(new File(inFile), inMime, inContent);
					} catch(Exception ex) {
						bOk = false;
						System.err.println("Error adding DataFile: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing input file or mime type of -ddoc-add command");
				}
			}
		}
		return bOk; // nothing to do?
	}


	/**
	 * Checks for commands related to
	 * displaying signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runListSignedDocCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-list")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_sdoc != null) {
				System.out.println("DigiDoc document: ");
				// display data files
				for(int i = 0; i < m_sdoc.countDataFiles(); i++) {
					DataFile df = m_sdoc.getDataFile(i);
					System.out.println("\tDataFile: " + df.getId() + " file: " + df.getFileName() +
						" mime: " + df.getMimeType() + " size: " + df.getSize()); 
				}
				// display signatures
				for(int i = 0; i < m_sdoc.countSignatures(); i++) {
					Signature sig = m_sdoc.getSignature(i);
					System.out.print("\tSignature: " + sig.getId() + " - ");
					KeyInfo keyInfo = m_sdoc.getSignature(i).getKeyInfo();
					String userId = keyInfo.getSubjectPersonalCode();
					String firstName = keyInfo.getSubjectFirstName();
					String familyName = keyInfo.getSubjectLastName();
					//String timeStamp = sdoc.getSignature(i).getSignedProperties().getSigningTime().toString();
					System.out.print(userId + "," + firstName + "," + familyName);
					ArrayList errs = sig.verify(m_sdoc, false, true);
					if(errs.size() == 0)
						System.out.println(" --> OK");
					else
						System.out.println(" --> ERROR");
					for(int j = 0; j < errs.size(); j++) 
						System.out.println("\t\t" + (DigiDocException)errs.get(j));                
				}
			
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * validating signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runValidateSignedDocCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-validate")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_sdoc != null) {
				System.out.println("Validating DigiDoc document: ");
				// display data files
				ArrayList errs = m_sdoc.validate(true);
				if(errs.size() == 0)
					System.out.println(" --> OK");
				else
					System.out.println(" --> ERROR");
				for(int j = 0; j < errs.size(); j++) 
					System.out.println("\t\t" + (DigiDocException)errs.get(j));                
			
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * displaying signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runNotarizeSignedDocCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-notarize")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_sdoc != null) {
				System.out.println("Notarizing digidoc: ");
				// display signatures
				for(int i = 0; i < m_sdoc.countSignatures(); i++) {
					Signature sig = m_sdoc.getSignature(i);
					System.out.print("\tSignature: " + sig.getId() + " - ");
					KeyInfo keyInfo = m_sdoc.getSignature(i).getKeyInfo();
					String userId = keyInfo.getSubjectPersonalCode();
					String firstName = keyInfo.getSubjectFirstName();
					String familyName = keyInfo.getSubjectLastName();
					//String timeStamp = sdoc.getSignature(i).getSignedProperties().getSigningTime().toString();
					System.out.println(userId + "," + firstName + "," + familyName);
					// get confirmation
					try {
						sig.getConfirmation();
					} catch(DigiDocException ex) {
						System.out.println("Error getting confirmation for: " + sig.getId() + 
								" - " + ex);
					}
					ArrayList errs = sig.verify(m_sdoc, false, true);
					if(errs.size() == 0)
						System.out.println(" --> OK");
					else
						System.out.println(" --> ERROR");
					for(int j = 0; j < errs.size(); j++) 
						System.out.println("\t\t" + (DigiDocException)errs.get(i));                
				}
			
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * displaying encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runListEncryptedDataCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-list")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_cdoc != null) {
				System.out.println("Encrypted document: ");
				// display data object
				System.out.print("\tEncryptedData "); 
				if(m_cdoc.getId() != null)
					System.out.print(" Id: " + m_cdoc.getId());
				if(m_cdoc.getType() != null)
					System.out.print(" type: " + m_cdoc.getType());
				if(m_cdoc.getMimeType() != null)
					System.out.print(" mime: " + m_cdoc.getMimeType());
				if(m_cdoc.getEncryptionMethod() != null)
					System.out.print(" algorithm: " + m_cdoc.getEncryptionMethod());
				System.out.println();
				// display meta data
				System.out.println("\tFORMAT: " + m_cdoc.getPropFormatName() +
						" VER: " + m_cdoc.getPropFormatVersion());
				System.out.println("\tLIBRARY: " + m_cdoc.getPropLibraryName() +
						" VER: " + m_cdoc.getPropLibraryVersion());
				int nFiles = m_cdoc.getPropOrigFileCount();
				for(int i = 0; i < nFiles; i++) {
					System.out.println("\tDF: " + m_cdoc.getPropOrigFileId(i) +
							" FILE: " + m_cdoc.getPropOrigFileName(i) +
							" SIZE: " + m_cdoc.getPropOrigFileSize(i) +
							" MIME: " + m_cdoc.getPropOrigFileMime(i));					
				}
				// display transport keys
				for(int i = 0; i < m_cdoc.getNumKeys(); i++) {
					EncryptedKey ekey = m_cdoc.getEncryptedKey(i);
					System.out.print("\tEncryptedKey");
					if(ekey.getId() != null)
						System.out.print(" Id: " + ekey.getId());
					if(ekey.getRecipient() != null)
						System.out.print(" Recipient: " + ekey.getRecipient());
					if(ekey.getKeyName() != null)
						System.out.print(" key-name: " + ekey.getKeyName());
					if(ekey.getCarriedKeyName() != null)
						System.out.print(" carried-key-name: " + ekey.getCarriedKeyName());
					if(ekey.getEncryptionMethod() != null)
						System.out.print("\n\t\talgorithm: " + ekey.getEncryptionMethod());
					if(ekey.getRecipientsCertificate() != null) 
						System.out.print("\n\t\tCERT: " + ekey.getRecipientsCertificate().getSubjectDN().getName());
					System.out.println();
				}
				// encryption properties
				System.out.print("\tEncryptionProperties");
				if(m_cdoc.getEncryptionPropertiesId() != null)
					System.out.print(" Id: " + m_cdoc.getEncryptionPropertiesId());
				System.out.println();
				for(int i = 0; i < m_cdoc.getNumProperties(); i++) {
					EncryptionProperty eprop = m_cdoc.getProperty(i);
					System.out.print("\t\tEncryptionProperty");
					if(eprop.getId() != null)
						System.out.print(" Id: " + eprop.getId());
					if(eprop.getTarget() != null)
						System.out.print(" Target: " + eprop.getTarget());
					if(eprop.getName() != null)
						System.out.print(" Name: " + eprop.getName());
					if(eprop.getContent() != null)
						System.out.print(" --> " + eprop.getContent());
					System.out.println();
				}
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}

	/**
	 * Checks for commands related to
	 * displaying encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runValidateEncryptedDataCmds(String[] args)
	{
		boolean bFound = false;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-validate")) {
				bFound = true;
				break;
			}
		}
		if(bFound) {
			if(m_cdoc != null) {
				System.out.println("Validating Encrypted document: ");
				// display data files
				ArrayList errs = m_cdoc.validate();
				if(errs.size() == 0)
					System.out.println(" --> OK");
				else
					System.out.println(" --> ERROR");
				for(int j = 0; j < errs.size(); j++) 
					System.out.println("\t\t" + (DigiDocException)errs.get(j)); 
				
			} else
				return false; // nothing read in to display
		}			
		return true; // nothing to do?
	}
	
	/**
	 * Checks for commands related to
	 * checking certificates
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runCheckCertCmds(String[] args)
	{
		boolean bOk = true;
		String inFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-check-cert")) {
				if(i < args.length - 2) {
					inFile = args[i+1];
					break;
				}
				else
					bOk = false;
			}
		}
		if(bOk && inFile != null) {
			System.out.println("Reading certificate file: " + inFile);
			try {
				NotaryFactory notFac = ConfigManager.
						instance().getNotaryFactory();
				X509Certificate cert = SignedDoc.readCertificate(new File(inFile));
				notFac.checkCertificate(cert);
				System.out.println("Certificate is OK");
			    bOk = true;
			} catch(Exception ex) {
				bOk = false;
				System.err.println("Error checking certificate: " + inFile + " - " + ex);
				ex.printStackTrace(System.err);
			}
		}			
		return bOk;
	}
	
	/**
	 * Checks for commands related to
	 * reading signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runReadSignedDocCmds(String[] args)
	{
		boolean bOk = true;
		String inFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-ddoc-in")) {
				if(i < args.length - 2) {
					inFile = args[i+1];
					break;
				}
				else
					bOk = false;
			}
		}
		if(bOk && inFile != null) {
			System.out.println("Reading digidoc file: " + inFile);
			try {
				DigiDocFactory digFac = ConfigManager.
						instance().getDigiDocFactory();
				m_sdoc = digFac.readSignedDoc(inFile);
			    bOk = true;
			} catch(Exception ex) {
				bOk = false;
				System.err.println("Error reading digidoc: " + inFile + " - " + ex);
				ex.printStackTrace(System.err);
			}
		}			
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * reading encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runReadEncryptedDataCmds(String[] args)
	{
		boolean bOk = true;
		String inFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-in")) {
				if(i < args.length - 2) {
					inFile = args[i+1];
					break;
				}
				else
					bOk = false;
			}
		}
		if(bOk && inFile != null) {
			System.out.println("Reading encrypted file: " + inFile);
			try {
				EncryptedDataParser dencFac =  ConfigManager.
					instance().getEncryptedDataParser();
				m_cdoc = dencFac.readEncryptedData(inFile);
				bOk = true;
			} catch(Exception ex) {
				bOk = false;
				System.err.println("Error reading encrypted file: " + inFile + " - " + ex);
				ex.printStackTrace(System.err);
			}
		}			
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * reading signed documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runEncryptEncryptedDataCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String inFile = null, outFile = null;
		//int nCompressOption = EncryptedData.DENC_COMPRESS_NEVER;
		int nCompressOption = EncryptedData.DENC_COMPRESS_BEST_EFFORT;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-encrypt")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(outFile != null && inFile != null) {
				System.out.println("Encrypting file: " + inFile + " to: " + outFile);
				try {
					byte[] inData = SignedDoc.readFile(new File(inFile));
					// TODO: check cdoc existencs
					m_cdoc.setData(inData);
					m_cdoc.setDataStatus(EncryptedData.DENC_DATA_STATUS_UNENCRYPTED_AND_NOT_COMPRESSED);
					m_cdoc.addProperty(EncryptedData.ENCPROP_FILENAME, inFile);
					m_cdoc.encrypt(nCompressOption);
					FileOutputStream fos = new FileOutputStream(outFile);
					fos.write(m_cdoc.toXML());
					fos.close();
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("Error encrypting file: " + inFile + " - " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file or output file of the -cdoc-encrypt command");
			}
		}	
		return bOk;
	}
	
	/**
	 * Checks for commands related to
	 * decrypting encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedDataCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String pin = null, outFile = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(pin != null && outFile != null) {
				System.out.println("Decrypting to: " + outFile);
				try {
					// TODO: check cdoc existencs
					m_cdoc.decrypt(0, 0, pin);
					FileOutputStream fos = new FileOutputStream(outFile);
					fos.write(m_cdoc.getData());
					fos.close();
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("Error decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing pin or output file of the -cdoc-decrypt command");
			}
		}	
		return bOk;
	}
	
	/**
	 * Checks for commands related to
	 * decrypting large encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runDecryptEncryptedStreamCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String pin = null, outFile = null, inFile = null, recvName = null;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-decrypt-stream")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					recvName = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					pin = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(pin != null && outFile != null && inFile != null && recvName != null) {
				System.out.println("Decrypting: " + inFile + " to: " + outFile + " recv: " + recvName);
				try {
					FileInputStream fis = new FileInputStream(inFile); 
					FileOutputStream fos = new FileOutputStream(outFile);
					EncryptedStreamParser streamParser = ConfigManager.instance().getEncryptedStreamParser();
					streamParser.decryptStreamUsingRecipientName(fis, fos, 0, pin, recvName);
					fos.close();
					fis.close();
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("Error decrypting file: " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file, recipient name, pin or output file of the -cdoc-decrypt-stream command");
			}
		}	
		return bOk;
	}

	/**
	 * Checks for commands related to
	 * encrypting big files
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runEncryptStreamCmds(String[] args)
	{
		boolean bOk = true, bFound = false;
		String inFile = null, outFile = null;
		int nCompressOption = EncryptedData.DENC_COMPRESS_ALLWAYS;
		//int nCompressOption = EncryptedData.DENC_COMPRESS_NEVER;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-encrypt-stream")) {
				bFound = true;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					inFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					outFile = args[i+1];
					i++;
				}
			}
		}
		if(bFound) {
			if(outFile != null && inFile != null) {
				System.out.println("Encrypting file: " + inFile + " to: " + outFile);
				try {
					// TODO: check cdoc existencs
					m_cdoc.addProperty(EncryptedData.ENCPROP_FILENAME, inFile);
					m_cdoc.encryptStream(new FileInputStream(inFile), new FileOutputStream(outFile), nCompressOption);
					bOk = true;
				} catch(Exception ex) {
					bOk = false;
					System.err.println("Error encrypting file: " + inFile + " - " + ex);
					ex.printStackTrace(System.err);
				}
			} else {
				bOk = false;
				System.err.println("Missing input file or output file of the -cdoc-encrypt-stream command");
			}
		}	
		return bOk;
	}
		
	/**
	 * Checks for commands related to
	 * adding recipients (EncryptedKey -s) encrypted documents
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runAddRecipientsCmds(String[] args)
	{
		boolean bOk = true;
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-cdoc-recipient")) {
				String certFile = null;
				String recipient = null;
				String keyName = null;
				String carriedKeyName = null;
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					certFile = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					recipient = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					keyName = args[i+1];
					i++;
				}
				if(i < args.length - 1 && !args[i+1].startsWith("-")) {
					carriedKeyName = args[i+1];
					i++;
				}
				if(certFile != null) {
					try {
						if(m_cdoc == null) {
							System.out.println("Creating encrypted document");
							m_cdoc = new EncryptedData(null, null, null, EncryptedData.DENC_XMLNS_XMLENC, EncryptedData.DENC_ENC_METHOD_AES128);
						}
						System.out.println("Adding recipient: " + certFile + ", " + recipient + ", " + keyName + ", " + carriedKeyName);
						X509Certificate recvCert = SignedDoc.readCertificate(new File(certFile));
						EncryptedKey ekey = new EncryptedKey(null, recipient, EncryptedData.DENC_ENC_METHOD_RSA1_5, keyName, carriedKeyName, recvCert);
						m_cdoc.addEncryptedKey(ekey);
					} catch(Exception ex) {
						bOk = false;
						System.err.println("Error adding EncryptedKey: " + ex);
						ex.printStackTrace(System.err);
					}
				} else {
					bOk = false;
					System.err.println("Missing certificate file of -cdoc-recipient command");
				}
			}
		}
		return bOk; // nothing to do?
	}

	
	/**
	 * Checks for configuration commands
	 * @param args command line arguments
	 * @return success flag
	 */
	private boolean runConfigCmds(String[] args)
	{
		boolean bOk = true;
		String cfgFile = "jar://jdigidoc.cfg"; // default value
		
		for(int i = 0; (args != null) && (i < args.length); i++) {
			if(args[i].equals("-config")) {
				if(i < args.length - 2) 
					cfgFile = args[i+1];
				else
					bOk = false;
			}
			if(args[i].equals("-?") || args[i].equals("-help")) {
				bOk = false;
				break;
			}
		}
		if(args.length == 0)  {
			System.out.println("args: " + args.length);
			bOk = false;
		}
		if(bOk) {
			System.out.println("Reading config file: " + cfgFile);
			bOk = ConfigManager.init(cfgFile);
		}			
		return bOk;
	}
	
	/**
	 * run-loop for jdigidoc. Evaluates the command line arguments
	 * and executes the commands
	 * @param args command line arguments
	 */
	public void run(String[] args)
	{
		boolean bOk = true;
		// check config file
		bOk = runConfigCmds(args);
		// checking certificates
		if(bOk)
			bOk = runCheckCertCmds(args);
		// reading of digidoc files
		if(bOk)
			bOk = runReadSignedDocCmds(args);
		// creating digidocs
		if(bOk)
			bOk = runNewSignedDocCmds(args);
		// adding data files
		if(bOk)
			bOk = runAddSignedDocCmds(args);
		// signing digidoc-s
		if(bOk)
			bOk = runSignSignedDocCmds(args);
		// notarizing digidoc-s
		if(bOk)
			bOk = runNotarizeSignedDocCmds(args);
		// writing digidoc's
		if(bOk)
			bOk = runWriteSignedDocCmds(args);
		// display signed doc
		if(bOk)
			bOk = runListSignedDocCmds(args);
		// validate signed doc
		if(bOk)
			bOk = runValidateSignedDocCmds(args);
		
		// read encrypted files
		if(bOk)
			bOk = runReadEncryptedDataCmds(args);
		// add recipients
		if(bOk)
			bOk = runAddRecipientsCmds(args);
		// encrypt data
		if(bOk)
			bOk = runEncryptEncryptedDataCmds(args);
		// encrypt data
		if(bOk)
			bOk = runEncryptStreamCmds(args);
		// decrypt data
		if(bOk)
			bOk = runDecryptEncryptedDataCmds(args);
		// decrypt data
		if(bOk)
			bOk = runDecryptEncryptedStreamCmds(args);
		// display encrypted doc
		if(bOk)
			bOk = runListEncryptedDataCmds(args);
		// validate encrypted doc
		if(bOk)
			bOk = runValidateEncryptedDataCmds(args);

		
		if(!bOk) {
			System.err.println("USAGE: ee.sk.test.jdigidoc [commands]");
			System.err.println("\t-? or -help - displays this help screen");
			System.err.println("\t-config <configuration-file> [default: jar://jdigidoc.cfg]");
			System.err.println("\t-check-cert <certficate-file-in-pem-format>");
			
			System.err.println("\t-ddoc-in <input-digidoc-file>");
			System.err.println("\t-ddoc-new [format] [version]");
			System.err.println("\t-ddoc-add <input-file> <mime-typ> [content-type]");
			System.err.println("\t-ddoc-sign <pin-code> [manifest] [country] [state] [city] [zip]");
			System.err.println("\t-ddoc-out <ouput-file>");			
			System.err.println("\t-ddoc-list");
			System.err.println("\t-ddoc-validate");

			System.err.println("\t-cdoc-in <input-encrypted-file>");
			System.err.println("\t-cdoc-list");
			System.err.println("\t-cdoc-validate");
			System.err.println("\t-cdoc-recipient <certificate-file> [recipient] [KeyName] [CarriedKeyName]");
			System.err.println("\t-cdoc-encrypt <input-file> <output-file>");
			System.err.println("\t-cdoc-encrypt-stream <input-file> <output-file>");
			System.err.println("\t-cdoc-decrypt <pin> <output-file>");
			System.err.println("\t-cdoc-decrypt-stream <input-file> <recipient> <pin> <output-file>");
			
		}
	}

	/**
	 * jdigidoc's main routine.
	 * @param args command line arguments
	 */
	public static void main(String[] args) 
	{
		Date ds, de;
		jdigidoc prog;
		// print program name & version
		System.out.println(SignedDoc.LIB_NAME + " - " + SignedDoc.LIB_VERSION);
		ds = new Date();
		prog = new jdigidoc();
		prog.run(args);
		de = new Date();
		System.out.println(SignedDoc.LIB_NAME + " end, time: " + ((de.getTime() - ds.getTime()) / 1000) + " [sek]" );
	}
}

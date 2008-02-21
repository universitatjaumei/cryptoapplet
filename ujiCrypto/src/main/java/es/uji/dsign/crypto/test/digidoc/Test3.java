/*
 * Test3.java
 *
 * Created on den 7 januari 2003, 07:41
 */

package es.uji.dsign.crypto.test.digidoc;
import java.io.*;
import java.util.zip.*;
import java.security.*;

import es.uji.dsign.crypto.digidoc.Base64Util;

/**
 * Tests reading zip files 
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Test3 {
    private static String testDirName = "C:\\veiko\\work\\sk\\JDigiDoc\\";
    private static String zipFileName = "test1.zip";
    private static String zipEntryName = "ARARVE.PRG";
        
    /** Creates new Test3 */
    public Test3() {
    }

    public static void main(String[] args) {
        try {
            ZipFile zipFile = new ZipFile(testDirName + zipFileName);
            ZipEntry ze = zipFile.getEntry(zipEntryName);
            byte[] digest1 = getZipDigest(zipFile, ze, true);
            System.out.println("Digest1: " + Base64Util.encode(digest1));
            byte[] digest2 = getZipDigest(zipFile, ze, false);
            System.out.println("Digest2: " + Base64Util.encode(digest2));
            
        } catch(Exception ex) {
            System.out.println("Error: " + ex.toString());
            ex.printStackTrace(System.out);
        }
    }
    
    private static byte[] getZipDigest(ZipFile zipFile, ZipEntry ze, boolean zip)
        throws ZipException, IOException, Exception
    {
        System.out.println("z2e: " + ze.toString() );
        InputStream is = null;
        if(zip)
            is = zipFile.getInputStream(ze);
        else
            is = new FileInputStream(testDirName + ze.toString());
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] buf = new byte[1024];
        int count;
        while ((count = is.read(buf)) != -1)
        {
            System.out.println("Count: " + count);
            sha.update(buf, 0, count);
        }
        is.close();
        return sha.digest();
    }

}

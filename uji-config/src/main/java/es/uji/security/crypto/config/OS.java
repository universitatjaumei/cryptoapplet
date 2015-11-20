package es.uji.security.crypto.config;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;

public class OS
{

    public static byte[] getBytesFromFile(File file) throws IOException
    {
        InputStream is = new FileInputStream(file);

        // Get the size of the file
        long length = file.length();

        if (length > Integer.MAX_VALUE)
        {
            // File is too large
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int) length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
                && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0)
        {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length)
        {
            throw new IOException("Could not completely read file " + file.getName());
        }

        // Close the input stream and return bytes
        is.close();
        return bytes;
    }
    
    public static String getSystemTmpDir(){
    	
    	//System.out.println("Got System.getProperty(java.io.tmpdir): " + System.getProperty("java.io.tmpdir") );
    	
    	return System.getProperty("java.io.tmpdir");
    }


    public static String stackTraceToString(Exception exc){
    	
    	byte b[];
    	
    	try{
    		PipedInputStream pInput=new PipedInputStream();
    		PipedOutputStream pOutput=new PipedOutputStream(pInput);
    		PrintStream pw=new PrintStream(pOutput);

    		exc.printStackTrace(pw);

    		b=new byte[pInput.available()];
    		pInput.read(b,0,pInput.available());
    	}
    	catch (Exception e){
    		return "Cannot get StackTrace - no info";
    	}
    	return new String(b);    
    }

    
    public static byte[] inputStreamToByteArray(InputStream in) throws IOException
    {
        byte[] buffer = new byte[2048];
        int length = 0;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        while ((length = in.read(buffer)) >= 0)
        {
            baos.write(buffer, 0, length);
        }

        return baos.toByteArray();
    }

    public static void dumpToFile(String fileName, byte[] data) throws IOException
    {
        if (fileName != null && fileName.length() > 0)
        {
            FileOutputStream fos = new FileOutputStream(fileName);
            fos.write(data);
            fos.flush();
            fos.close();
        }
    }
    
    public static void dumpToFile(File file, InputStream in) throws IOException
    {
    	System.out.println("Dumping to file available: " + in.available());
    	
        if (file != null /*&& file.length() > 0*/)
        {
        	byte[] buffer = new byte[2048];
            int length = 0;

            FileOutputStream fos = new FileOutputStream(file);

            while ((length = in.read(buffer)) >= 0)
            {
                fos.write(buffer, 0, length);
            }
            
            fos.close();
        }
    }
    

    public static void copyfile(String srFile, String dtFile) throws FileNotFoundException, IOException{

    	File f1 = new File(srFile);
    	File f2 = new File(dtFile);
    	
    	if (! f2.exists() ){
    		InputStream in = new FileInputStream(f1);
    		OutputStream out = new FileOutputStream(f2);

    		byte[] buf = new byte[1024];
    		int len;
    		while ((len = in.read(buf)) > 0){
    			out.write(buf, 0, len);
    		}
    		in.close();
    		out.close();
    	}
    }
    
    public static String[] getAllSystemLibDirectories(){

    	ArrayList<String> res = new ArrayList<String>();

    	if (OS.isLinux()){
    		File folder = new File("/etc/ld.so.conf.d/");
    		File[] listOfFiles = folder.listFiles();
    		if (listOfFiles !=null){
    			for (int i = 0; i < listOfFiles.length; i++) {
    				if (listOfFiles[i].isFile()) {
    					try{
    						FileInputStream fstream = new FileInputStream(listOfFiles[i]);
    						DataInputStream in = new DataInputStream(fstream);
    						BufferedReader br = new BufferedReader(new InputStreamReader(in));
    						String strLine;
    						while ((strLine = br.readLine()) != null)   {
    							if (!strLine.trim().startsWith("#")){
    								res.add(strLine);
    								//System.out.println (strLine);
    							}
    						}
    						in.close();
    					}catch (Exception e){
    						// Just doing nothing, without adding anything to res.
    						// System.err.println("Error: " + e.getMessage());
    					}
    				}
    			}
    		}
    	}
    	else if (OS.isMac()){
    		res.add("/Library");
    	}
    	else{
    		res.add(System.getenv("SystemDirectory"));
    	}

    	String[] sRes= new String[res.size()]; 
    	res.toArray(sRes);

    	return sRes;
    }
    
    
    public static String getOS()
    {
        return System.getProperty("os.name").toLowerCase();
    }

    public static boolean isWindowsXP()
    {
        return (getOS().indexOf("windows xp") > -1);
    }

    public static boolean isWindows2000()
    {
        return (getOS().indexOf("windows 2000") > -1);
    }

    public static boolean isWindows2003()
    {
        return (getOS().indexOf("windows 2003") > -1);
    }

    public static boolean isWindows2008()
    {
        return (getOS().indexOf("windows 2008") > -1);
    }

    public static boolean isWindowsVista()
    {
        return (getOS().indexOf("vista") > -1);
    }

    public static boolean isWindows7()
    {
        return (getOS().indexOf("windows 7") > -1);
    }

    public static boolean isWindows8()
    {
        return (getOS().indexOf("windows 8") > -1);
    }

    public static boolean isWindowsNT()
    {
        return (getOS().indexOf("nt") > -1);
    }

    public static boolean isMac()
    {
        return (getOS().indexOf("mac") > -1);
    }

    public static boolean isLinux()
    {
        return (getOS().indexOf("linux") > -1);
    }

    public static boolean isWindowsUpperEqualToNT()
    {
        return (isWindowsNT() ||
                isWindows2000() ||
                isWindowsXP()||
                isWindows2003() ||
                isWindows2008() ||
                isWindowsVista() ||
                isWindows7() ||
                isWindows8());
    }
    
    public static boolean isJavaUpperEqualTo6(){
    	
    	 String version = System.getProperty("java.version");
         return (version.indexOf("1.6") > -1 || version.indexOf("1.7") > -1 || version.indexOf("1.8") > -1);
    }

    public static boolean isJavaUpperEqualTo8() {
        String javaSpecVersion = System.getProperty("java.specification.version"); // expected 1.7, 1.8, etc
        int numericJavaSpecVersion = Integer.parseInt(javaSpecVersion.replace(".", ""));
        return numericJavaSpecVersion >= 18;
    }

    // TODO check if there is already another way to detect x86_64 platforms in this project
    public static boolean is64BitJava() {
        return System.getProperty("os.arch").contains("64");
    }

    /*public static void main(String[] args){
    	String[] all= OS.getAllSystemLibDirectories();
    	for (String i: all){
    		System.out.println(i);
    	}
    }*/
}

/*
 * ConvertUtils.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
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

package es.uji.security.crypto.openxades.digidoc.utils;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.util.ISO8601DateParser;

/**
 * Miscellaneous data conversion utility methods
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class ConvertUtils
{
    private static final String m_dateFormat = "yyyy.MM.dd'T'HH:mm:ss'Z'";
    private static final String m_dateFormatXAdES = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    /**
     * Helper method to convert a Date object to xsd:date format
     * 
     * @param d
     *            input data
     * @param ddoc
     *            signed doc
     * @return stringified date (xsd:date)
     * @throws DigiDocException
     *             for errors
     */
    public static String date2string(Date d, SignedDoc ddoc) throws DigiDocException
    {
        String str = null;
        try
        {
            SimpleDateFormat f = new SimpleDateFormat(
                    ((ddoc.getVersion().equals(SignedDoc.VERSION_1_3) || ddoc.getVersion().equals(
                            SignedDoc.VERSION_1_4)) ? m_dateFormatXAdES : m_dateFormat));
            f.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
            str = f.format(d);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_DATE_FORMAT);
        }
        return str;
    }

    /**
     * Helper method to convert a string to a Date object from xsd:date format
     * 
     * @param str
     *            stringified date (xsd:date
     * @param ddoc
     *            signed doc
     * @return Date object
     * @throws DigiDocException
     *             for errors
     */
    public static Date string2date(String str, SignedDoc ddoc) throws DigiDocException
    {
        Date result = null;
        
        try
        {
            result = ISO8601DateParser.parse(str);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_DATE_FORMAT);
        }
        
        return result;
    }

    /**
     * Helper method to convert a string to a BigInteger object
     * 
     * @param str
     *            stringified date (xsd:date
     * @return BigInteger object
     * @throws DigiDocException
     *             for errors
     */
    public static BigInteger string2bigint(String str) throws DigiDocException
    {
        BigInteger b = null;
        try
        {
            b = new BigInteger(str);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_NUMBER_FORMAT);
        }
        return b;
    }

    /**
     * Helper method to convert a String to UTF-8
     * 
     * @param data
     *            input data
     * @param codepage
     *            codepage of input bytes
     * @return UTF-8 string
     * @throws DigiDocException
     *             for errors
     */
    public static byte[] data2utf8(byte[] data, String codepage) throws DigiDocException
    {
        byte[] bdata = null;
        try
        {
            String str = new String(data, codepage);
            bdata = str.getBytes("UTF-8");
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return bdata;
    }

    /**
     * Converts to UTF-8 byte array
     * 
     * @param str
     *            input data
     * @return byte array of string in desired codepage
     * @throws DigiDocException
     *             for errors
     */
    public static byte[] str2data(String str) throws DigiDocException
    {
        return str2data(str, "UTF-8");
    }

    /**
     * Helper method to convert a String to byte array of any codepage
     * 
     * @param data
     *            input data
     * @param codepage
     *            codepage of output bytes
     * @return byte array of string in desired codepage
     * @throws DigiDocException
     *             for errors
     */
    public static byte[] str2data(String str, String codepage) throws DigiDocException
    {
        byte[] bdata = null;
        try
        {
            bdata = str.getBytes(codepage);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return bdata;
    }

    /**
     * Helper method to convert a String to UTF-8
     * 
     * @param data
     *            input data
     * @param codepage
     *            codepage of input bytes
     * @return UTF-8 string
     * @throws DigiDocException
     *             for errors
     */
    public static String data2str(byte[] data, String codepage) throws DigiDocException
    {
        String str = null;
        try
        {
            str = new String(data, codepage);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return str;
    }

    /**
     * Helper method to convert an UTF-8 String to non-utf8 string
     * 
     * @param UTF
     *            -8 input data
     * @return normal string
     * @throws DigiDocException
     *             for errors
     */
    public static String utf82str(String data) throws DigiDocException
    {
        String str = null;
        
        try
        {
            byte[] bdata = data.getBytes();
            str = new String(bdata, "UTF-8");
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        
        return str;
    }

    /**
     * Checks if the certificate identified by this CN is a known OCSP responders cert
     * 
     * @param cn
     *            certificates common name
     * @return true if this is a known OCSP cert
     */
    public static boolean isKnownOCSPCert(String cn)
    {
        ConfigManager conf = ConfigManager.getInstance();
        
        int nOcsps = conf.getIntProperty("DIGIDOC_OCSP_COUNT", 0);
        
        for (int i = 0; i < nOcsps; i++)
        {
            String s = conf.getProperty("DIGIDOC_OCSP" + (i + 1) + "_CN");
            
            if (s != null && s.equals(cn))
            {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Checks if the certificate identified by this CN is a known TSA cert
     * 
     * @param cn
     *            certificates common name
     * @return true if this is a known TSA cert
     */
    public static boolean isKnownTSACert(String cn)
    {
        ConfigManager conf = ConfigManager.getInstance();
        
        int nTsas = conf.getIntProperty("DIGIDOC_TSA_COUNT", 0);
        
        for (int i = 0; i < nTsas; i++)
        {
            String s = conf.getProperty("DIGIDOC_TSA" + (i + 1) + "_CN");
            
            if (s != null && s.equals(cn))
            {
                return true;
            }
        }
        
        return false;
    }

}

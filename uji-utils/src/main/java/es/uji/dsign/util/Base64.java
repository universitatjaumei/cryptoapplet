/*
 Copyright 2006 IT Practice A/S
 Copyright 2006 TDC Totallsninger A/S
 Copyright 2006 Jens Bo Friis
 Copyright 2006 Preben Rosendal Valeur
 Copyright 2006 Carsten Raskgaard


 This file is part of OpenSign.

 OpenSign is free software; you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation; either version 2.1 of the License, or
 (at your option) any later version.

 OpenSign is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with OpenOcesAPI; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


 Note to developers:
 If you add code to this file, please take a minute to add an additional
 copyright statement above and an additional
 @author statement below.
 */

/* $Id: Base64.java,v 1.4 2006/06/21 19:10:07 cara Exp $ */

package es.uji.dsign.util;

/**
 * This class provides encode/decode for RFC 2045 Base64 as defined by RFC 2045, N. Freed and N.
 * Borenstein. RFC 2045: Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet
 * Message Bodies. Reference 1996 Available at: http://www.ietf.org/rfc/rfc2045.txt This class is
 * used by XML Schema binary format validation
 * 
 * 
 * @author Jeffrey Rodriguez
 */

public final class Base64
{
    static private final int BASELENGTH = 255;
    static private final int LOOKUPLENGTH = 64;
    static private final int TWENTYFOURBITGROUP = 24;
    static private final int EIGHTBIT = 8;
    static private final int SIXTEENBIT = 16;
    static private final int SIXBIT = 6;
    static private final int FOURBYTE = 4;
    static private final int SIGN = -128;
    static private final byte PAD = (byte) '=';
    static private final boolean fDebug = false;
    static private byte[] base64Alphabet = new byte[BASELENGTH];
    static private byte[] lookUpBase64Alphabet = new byte[LOOKUPLENGTH];

    static
    {
        for (int i = 0; i < BASELENGTH; i++)
        {
            base64Alphabet[i] = -1;
        }
        for (int i = 'Z'; i >= 'A'; i--)
        {
            base64Alphabet[i] = (byte) (i - 'A');
        }
        for (int i = 'z'; i >= 'a'; i--)
        {
            base64Alphabet[i] = (byte) (i - 'a' + 26);
        }

        for (int i = '9'; i >= '0'; i--)
        {
            base64Alphabet[i] = (byte) (i - '0' + 52);
        }

        base64Alphabet['+'] = 62;
        base64Alphabet['/'] = 63;

        for (int i = 0; i <= 25; i++)
        {
            lookUpBase64Alphabet[i] = (byte) ('A' + i);
        }
        for (int i = 26, j = 0; i <= 51; i++, j++)
        {
            lookUpBase64Alphabet[i] = (byte) ('a' + j);
        }
        for (int i = 52, j = 0; i <= 61; i++, j++)
        {
            lookUpBase64Alphabet[i] = (byte) ('0' + j);
        }

        lookUpBase64Alphabet[62] = (byte) '+';
        lookUpBase64Alphabet[63] = (byte) '/';
    }

    /**
     * Decodes Base64 data into octects
     * 
     * @param base64Data
     *            Byte array containing Base64 data
     * @return Array containind decoded data.
     */
    public static byte[] decode(byte[] base64Data)
    {
        int numberQuadruple = base64Data.length / FOURBYTE;
        byte decodedData[] = null;
        byte b1 = 0, b2 = 0, b3 = 0, b4 = 0, marker0 = 0, marker1 = 0;

        // Throw away anything not in base64Data
        // Adjust size

        int encodedIndex = 0;
        int dataIndex = 0;
        int pads = 0;
        decodedData = new byte[numberQuadruple * 3 + 1];

        for (int i = 0; i < numberQuadruple; i++)
        {
            dataIndex = i * 4;
            marker0 = base64Data[dataIndex + 2];
            marker1 = base64Data[dataIndex + 3];

            b1 = base64Alphabet[base64Data[dataIndex]];
            b2 = base64Alphabet[base64Data[dataIndex + 1]];

            if (marker0 != PAD && marker1 != PAD)
            { // No PAD e.g 3cQl
                b3 = base64Alphabet[marker0];
                b4 = base64Alphabet[marker1];

                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
                decodedData[encodedIndex + 1] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
                decodedData[encodedIndex + 2] = (byte) (b3 << 6 | b4);
            }
            else if (marker0 == PAD)
            { // Two PAD e.g. 3c[Pad][Pad]
                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
                decodedData[encodedIndex + 1] = (byte) ((b2 & 0xf) << 4);
                decodedData[encodedIndex + 2] = (byte) 0;
                pads += 2;
            }
            else if (marker1 == PAD)
            { // One PAD e.g. 3cQ[Pad]
                b3 = base64Alphabet[marker0];

                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
                decodedData[encodedIndex + 1] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
                decodedData[encodedIndex + 2] = (byte) (b3 << 6);
                pads++;
            }
            encodedIndex += 3;
        }

        byte[] out = new byte[decodedData.length - 1 - pads];
        System.arraycopy(decodedData, 0, out, 0, out.length);
        return out;
    }

    /**
     * Encodes hex octects into Base64 breaking the content in
     * 
     * 
     * @param binaryData
     *            Array containing binaryData
     * @return Encoded Base64 array
     */
    public static byte[] encode(byte[] binaryData, boolean splitColumns)
    {
        byte[] bstrSig = null, bstrAux = null;
        String strAux = new String(Base64.encode(binaryData));

        int i = 0;
        int len = strAux.length();
        bstrAux = strAux.getBytes();
        int mod = len % 64;

        if (mod == 0)
            bstrSig = new byte[(len + len / 64) - 1];
        else
            bstrSig = new byte[len + len / 64];

        int j = 0;

        for (i = 0; i < len; i++)
        {
            if (i % 64 == 0 && i != 0)
            {
                bstrSig[j++] = '\n';
            }
            bstrSig[j++] = bstrAux[i];

        }
        return bstrSig;
    }

    /**
     * Encodes hex octects into Base64
     * 
     * @param binaryData
     *            Array containing binaryData
     * @return Encoded Base64 array
     */
    public static byte[] encode(byte[] binaryData)
    {
        int lengthDataBits = binaryData.length * EIGHTBIT;
        int fewerThan24bits = lengthDataBits % TWENTYFOURBITGROUP;
        int numberTriplets = lengthDataBits / TWENTYFOURBITGROUP;
        byte encodedData[] = null;

        if (fewerThan24bits != 0) // data not divisible by 24 bit
        {
            encodedData = new byte[(numberTriplets + 1) * 4];
        }
        else
        {
            // 16 or 8 bit
            encodedData = new byte[numberTriplets * 4];
        }

        byte k = 0, l = 0, b1 = 0, b2 = 0, b3 = 0;

        int encodedIndex = 0;
        int dataIndex = 0;
        int i = 0;

        if (fDebug)
        {
            System.out.println("number of triplets = " + numberTriplets);
        }

        for (i = 0; i < numberTriplets; i++)
        {
            dataIndex = i * 3;
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            b3 = binaryData[dataIndex + 2];

            if (fDebug)
            {
                System.out.println("b1= " + b1 + ", b2= " + b2 + ", b3= " + b3);
            }

            l = (byte) (b2 & 0x0f);
            k = (byte) (b1 & 0x03);

            encodedIndex = i * 4;
            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) ((b1) >> 2 ^ 0xc0);

            byte val2 = ((b2 & SIGN) == 0) ? (byte) (b2 >> 4) : (byte) ((b2) >> 4 ^ 0xf0);
            byte val3 = ((b3 & SIGN) == 0) ? (byte) (b3 >> 6) : (byte) ((b3) >> 6 ^ 0xfc);

            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];

            if (fDebug)
            {
                System.out.println("val2 = " + val2);
                System.out.println("k4   = " + (k << 4));
                System.out.println("vak  = " + (val2 | (k << 4)));
            }

            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex + 2] = lookUpBase64Alphabet[(l << 2) | val3];
            encodedData[encodedIndex + 3] = lookUpBase64Alphabet[b3 & 0x3f];
        }

        // form integral number of 6-bit groups
        dataIndex = i * 3;
        encodedIndex = i * 4;

        if (fewerThan24bits == EIGHTBIT)
        {
            b1 = binaryData[dataIndex];
            k = (byte) (b1 & 0x03);
            if (fDebug)
            {
                System.out.println("b1=" + b1);
                System.out.println("b1<<2 = " + (b1 >> 2));
            }
            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) ((b1) >> 2 ^ 0xc0);
            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[k << 4];
            encodedData[encodedIndex + 2] = PAD;
            encodedData[encodedIndex + 3] = PAD;
        }
        else if (fewerThan24bits == SIXTEENBIT)
        {
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            l = (byte) (b2 & 0x0f);
            k = (byte) (b1 & 0x03);

            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) ((b1) >> 2 ^ 0xc0);
            byte val2 = ((b2 & SIGN) == 0) ? (byte) (b2 >> 4) : (byte) ((b2) >> 4 ^ 0xf0);

            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex + 2] = lookUpBase64Alphabet[l << 2];
            encodedData[encodedIndex + 3] = PAD;
        }

        return encodedData;
    }

    public static boolean isArrayByteBase64(byte[] arrayOctect)
    {
        int length = arrayOctect.length;

        if (length == 0)
        {
            return false;
        }

        for (int i = 0; i < length; i++)
        {
            if (Base64.isBase64(arrayOctect[i]) == false)
                return false;
        }

        return true;
    }

    public static boolean isBase64(byte octect)
    {
        // shall we ignore white space? JEFF??
        return (octect == PAD || base64Alphabet[octect] != -1);
    }

    public static boolean isBase64(String isValidString)
    {
        return (isArrayByteBase64(isValidString.getBytes()));
    }
}
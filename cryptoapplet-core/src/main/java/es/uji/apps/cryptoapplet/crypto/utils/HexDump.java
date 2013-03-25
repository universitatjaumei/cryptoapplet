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

/* $Id: HexDump.java,v 1.3 2006/04/17 21:08:26 cara Exp $ */

package es.uji.apps.cryptoapplet.crypto.utils;

/**
 * This class implements hex output functionality
 * 
 * @author Kim Rasmussen <kr@it-practice.dk>
 */

public final class HexDump
{
    static char[] hexstr = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
            'E', 'F' };

    /**
     * Convert byte value to hexadecimal string representation (for trace dumps)
     * 
     * @return java.lang.String
     * @param value
     *            byte
     * @param digits
     *            int
     */
    static String tohex(byte value, int digits)
    {
        return tohex((int) value, digits);
    }

    /**
     * Convert byte value to hexadecimal string representation (for trace dumps)
     * 
     * @return java.lang.String
     * @param value
     *            int
     * @param digits
     *            int
     */

    public static String tohex(int value, int digits)
    {
        char[] ret = new char[digits];
        int n;
        byte a;

        for (n = 0; n < digits; n++)
        {
            a = (byte) (value & 0x0F);
            value >>= 4;

            ret[digits - n - 1] = hexstr[a];
        }

        return String.valueOf(ret);
    }

    public static String xdump(char[] ch)
    {
        byte[] b = new byte[ch.length];

        for (int i = 0; i < ch.length; i++)
            b[i] = (byte) ch[i];

        return xdump(b);
    }

    /**
     * Dumps data block in hexadecimal representation (part of trace action)
     * 
     * @param bytes
     *            byte[]
     */
    public static String xdump(byte[] bytes)
    {
        if (bytes == null)
            return "null";
        int len = bytes.length;
        int ofs = 0, count = 0;
        int n;
        StringBuffer sb = new StringBuffer(80);
        StringBuffer outstr = new StringBuffer(5 * len);

        while (ofs < len)
        {
            count = (len - ofs) < 16 ? (len - ofs) : 16;

            sb.setLength(0);

            sb.append(tohex(ofs, 4));
            sb.append(": ");

            // First, the hex bytes
            for (n = 0; n < count; n++)
            {
                if (n == 8)
                    sb.append("- ");
                sb.append(tohex((int) bytes[ofs + n], 2));
                sb.append(' ');
            }

            // Then fill up with spaces
            for (n = count; n < 16; n++)
                sb.append("   ");

            if (count < 9) // Add the '- ' if we need it.
                sb.append("  ");

            // Seperate hex bytes from ascii chars
            sb.append(" ");

            // And last, the ascii characters
            for (n = 0; n < count; n++)
            {
                char b = (char) bytes[ofs + n];

                if (b >= (char) 32 && (char) b <= 127)
                    sb.append(b);
                else
                    sb.append('.');
            }

            sb.append("\r\n");
            outstr.append(sb.toString());
            // log(sb.toString());
            ofs += count;
        }

        return outstr.toString();
    }
}
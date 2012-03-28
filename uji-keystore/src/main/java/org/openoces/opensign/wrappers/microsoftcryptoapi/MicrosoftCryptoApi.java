/*
 Copyright 2006 IT Practice A/S
 Copyright 2006 TDC Totalløsninger A/S
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

/* $Id: MicrosoftCryptoApi.java,v 1.5 2006/04/17 21:08:27 cara Exp $ */

package org.openoces.opensign.wrappers.microsoftcryptoapi;

import java.math.BigInteger;
import java.util.Date;

/**
 * This class implements the java stub of the capi wrapper
 * 
 * @author Carsten Raskgaard <carsten@raskgaard.dk>
 */

public class MicrosoftCryptoApi
{
    public native void hello();

    public native byte[][] getCertificatesInSystemStore(String storeName);

    public native byte[] signMessage(byte[] toBeSigned, byte[] certificate);

    public native byte[] signHash(byte[] toBeSigned, byte[] certificate);

    public native int getCertificateVersion(byte[] certificate);

    public native byte[] digest(byte[] data, String algorithm);

    public native int getLastErrorCode();

    public native int getMajorVersion();

    public native int getMinorVersion();

    public native int getKeyUsage(byte[] certificate);

    private native String getSubjectDn(byte[] certificate);

    private native String getIssuerDn(byte[] certificate);

    private native byte[] getSerialNumber(byte[] certificate);

    private native long getNotAfter(byte[] certificate);

    private native long getNotBefore(byte[] certificate);

    /*
     * static { System.loadLibrary("MicrosoftCryptoApi_0_2"); }
     */

    public Date getNotBeforeDate(byte[] certificate)
    {
        return new Date(getNotBefore(certificate));
    }

    public Date getNotAfterDate(byte[] certificate)
    {
        return new Date(getNotAfter(certificate));
    }

    public BigInteger getSerialNumberBigInteger(byte[] certificate)
    {
        byte[] serialNumber = getSerialNumber(certificate);

        /* convert from little endian to big endian */
        for (int i = 0; i < (serialNumber.length / 2); i++)
        {
            int lowerIdx = i;
            int upperIdx = serialNumber.length - i - 1;
            byte b = serialNumber[lowerIdx];
            serialNumber[lowerIdx] = serialNumber[upperIdx];
            serialNumber[upperIdx] = b;
        }

        return new BigInteger(serialNumber);
    }

    public String getSubjectDnString(byte[] certificate)
    {
        String s = getSubjectDn(certificate);
        return s == null ? null : s.substring(0, s.length() - 1);
    }

    public String getIssuerDnString(byte[] certificate)
    {
        String s = getIssuerDn(certificate);
        return s == null ? null : s.substring(0, s.length() - 1);
    }
}
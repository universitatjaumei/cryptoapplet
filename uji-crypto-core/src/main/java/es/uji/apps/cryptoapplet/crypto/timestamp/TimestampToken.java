/*
 * @(#)TimestampToken.java	1.3 05/11/17
 *
 * Copyright 2006 Sun Microsystems, Inc. All rights reserved.
 * SUN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package es.uji.apps.cryptoapplet.crypto.timestamp;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

/**
 * This class provides the timestamp token info resulting from a successful timestamp request, as
 * defined in <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>.
 * 
 * The timestampTokenInfo ASN.1 type has the following definition:
 * 
 * <pre>
 * 
 *     TSTInfo ::= SEQUENCE {
 *         version                INTEGER  { v1(1) },
 *         policy                 TSAPolicyId,
 *         messageImprint         MessageImprint,
 *           -- MUST have the same value as the similar field in
 *           -- TimeStampReq
 *         serialNumber           INTEGER,
 *          -- Time-Stamping users MUST be ready to accommodate integers
 *          -- up to 160 bits.
 *         genTime                GeneralizedTime,
 *         accuracy               Accuracy                 OPTIONAL,
 *         ordering               BOOLEAN             DEFAULT FALSE,
 *         nonce                  INTEGER                  OPTIONAL,
 *           -- MUST be present if the similar field was present
 *           -- in TimeStampReq.  In that case it MUST have the same value.
 *         tsa                    [0] GeneralName          OPTIONAL,
 *         extensions             [1] IMPLICIT Extensions  OPTIONAL }
 *     Accuracy ::= SEQUENCE {
 *         seconds        INTEGER           OPTIONAL,
 *         millis     [0] INTEGER  (1..999) OPTIONAL,
 *         micros     [1] INTEGER  (1..999) OPTIONAL  }
 * 
 * </pre>
 * 
 * @since 1.5
 * @see Timestamper
 * @author Vincent Ryan
 */

public class TimestampToken
{

    private int version;
    private ObjectIdentifier policy;
    private BigInteger serialNumber;
    private AlgorithmId hashAlgorithm;
    private byte[] hashedMessage;
    private Date genTime;

    /**
     * Constructs an object to store a timestamp token.
     * 
     * @param status
     *            A buffer containing the ASN.1 BER encoding of the TSTInfo element defined in RFC
     *            3161.
     */
    public TimestampToken(byte[] timestampTokenInfo) throws IOException
    {
        if (timestampTokenInfo == null)
        {
            throw new IOException("No timestamp token info");
        }
        parse(timestampTokenInfo);
    }

    /**
     * Extract the date and time from the timestamp token.
     * 
     * @return The date and time when the timestamp was generated.
     */
    public Date getDate()
    {
        return genTime;
    }

    /*
     * Parses the timestamp token info.
     * 
     * @param timestampTokenInfo A buffer containing an ASN.1 BER encoded TSTInfo.
     * 
     * @throws IOException The exception is thrown if a problem is encountered while parsing.
     */
    private void parse(byte[] timestampTokenInfo) throws IOException
    {

        DerValue tstInfo = new DerValue(timestampTokenInfo);
        if (tstInfo.tag != DerValue.tag_Sequence)
        {
            throw new IOException("Bad encoding for timestamp token info");
        }
        // Parse version
        version = tstInfo.data.getInteger();

        // Parse policy
        policy = tstInfo.data.getOID();

        // Parse messageImprint
        DerValue messageImprint = tstInfo.data.getDerValue();
        hashAlgorithm = AlgorithmId.parse(messageImprint.data.getDerValue());
        hashedMessage = messageImprint.data.getOctetString();

        // Parse serialNumber
        serialNumber = tstInfo.data.getBigInteger();

        // Parse genTime
        genTime = tstInfo.data.getGeneralizedTime();

        // Parse optional elements, if present
        if (tstInfo.data.available() > 0)
        {

            // Parse accuracy
            // Parse ordering
            // Parse nonce
            // Parse tsa
            // Parse extensions
        }
    }
}

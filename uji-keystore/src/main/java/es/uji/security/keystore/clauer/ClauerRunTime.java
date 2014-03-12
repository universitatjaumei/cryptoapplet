package es.uji.security.keystore.clauer;

import es.uji.security.keystore.clauer.ClauerHandle;
import es.uji.security.util.net.SocketDataInputStreamReader;

import java.net.Socket;
import java.io.IOException;

/**
 * This class will implement all the functions of the protocol by the time it will implement just
 * the necessary ones
 */

public class ClauerRunTime
{
    private ClauerHandle clhandle = new ClauerHandle();
    private boolean _sessionStarted = false;
    private SocketDataInputStreamReader sDataReader;

    private byte FUNC_ENUM = 0;
    private byte FUNC_START_SESSION = 1;
    private byte FUNC_READ_INFO_BLOCK = 5;
    private byte FUNC_FIND_FIRST_TYPE_BLOCK = 7;
    private byte FUNC_FIND_NEXT_TYPE_BLOCK = 8;
    private byte FUNC_READ_ALL_TYPE_OBJECTS = 9;
    private byte FUNC_CACHE_REFRESH = 15;
    private byte FUNC_CLOSE_SESSION = 20;
    private int MAX_PATH_LEN = 256;

    // private Logger log;

    public ClauerRunTime()
    {
        // log = Logger.getLogger(CertificateChooser.class);
    }

    public boolean isRunTimeRunning()
    {
        try
        {
            Socket s = new Socket("127.0.0.1", 969);
            s.close();
        }
        catch (Exception e)
        {
            return false;
        }

        return true;
    }

    /**
     * Returns a String[] with the clauers plugged in
     */
    public String[] enumerateDevices() throws IOException, Exception
    {
        int numDev, pathLen, i = 0;
        byte[] bPath;
        String[] res = null;

        // log.debug("Start: Enumerating devices ");
        clhandle.s = new Socket("localhost", 969);
        clhandle.initInputOutput();
        sDataReader = new SocketDataInputStreamReader(clhandle.inStream);

        clhandle.outStream.write(this.FUNC_ENUM);
        numDev = clhandle.inStream.read();
        res = new String[numDev];

        while (i < numDev)
        {
            pathLen = sDataReader.readInt();

            /*
             * Client sends little endian data, readInt function represents the integer as big
             * endian so we must reverse the bytes.
             */

            // pathLen= Integer.reverseBytes(pathLen);
            if (pathLen >= 256)
            {
                throw new Exception("DevicePathTooLong");
            }
            else
            {
                bPath = new byte[pathLen];
                bPath = sDataReader.readByteArray(pathLen);
                // clhandle.inStream.read(bPath, 0, pathLen);
                res[i] = new String(bPath);
            }

            i++;
        }

        clhandle.cleanUp();

        // log.debug("End: Enumerating devices ");
        return res;
    }

    public boolean startSession(String device, String pwd, ClauerHandle clHandle)
            throws IOException
    {
        int err;

        // log.debug("Start: StartSession");
        clhandle.s = new Socket("localhost", 969);
        clhandle.initInputOutput();
        sDataReader = new SocketDataInputStreamReader(clhandle.inStream);

        clhandle.outStream.write(this.FUNC_START_SESSION);
        clhandle.outStream.writeInt(Integer.reverseBytes(device.length()));

        clhandle.outStream.write(device.getBytes());

        /*
         * Sending password length corresponding to an unauthenticated session.
         */
        clhandle.outStream.write(pwd.length());

        if (pwd.length() != 0)
        {
            /* In this case we are under an authenticated session */
            clhandle.outStream.write(pwd.getBytes());
        }

        err = clhandle.inStream.read();

        if (err != 0)
        {
            return false;
        }
        else
        {
            byte[] devId = new byte[20];
            devId = sDataReader.readByteArray(20);
            // clhandle.inStream.read(devId,0,20);
            clhandle.setId(devId);
        }

        /*
         * It prints clauer id (debug porpouses)
         */
        // HexEncoder h= new HexEncoder();
        // h.encode(clhandle.idDisp, 0, 20, System.out);
        _sessionStarted = true;

        // log.debug("End: Start Session ");

        return true;
    }

    public byte[][] readAllTypeObjects(byte type) throws IOException, Exception
    {
        // log.debug("Start: readAllTypeObjects ");

        if (!_sessionStarted)
        {
            throw new Exception("UnstartedSessionAgainsClauer");
        }

        byte[][] bRes;

        clhandle.outStream.write(this.FUNC_READ_ALL_TYPE_OBJECTS);
        clhandle.outStream.write(type);

        int err = clhandle.inStream.read();

        if (err != 0)
        {
            // System.out.println("Exception!!! ");
            throw new Exception("ErrorGettingCertificates");
        }
        else
        {
            int ncerts = sDataReader.readInt();
            // System.out.println("\nNCERTS: " + ncerts);

            bRes = new byte[ncerts][10240];

            /* By the time block position is ignored */
            for (int j = 0; j < ncerts; j++)
            {
                sDataReader.readInt();
            }

            for (int j = 0; j < ncerts; j++)
            {
                bRes[j] = sDataReader.readByteArray(10240);
                // clhandle.inStream.read(bRes[j],0,10240);
                // System.out.println("Raded: " + readed);
            }
        }

        // log.debug("End: ReadAllTypeObjects ");
        return bRes;
    }

    public int readFirstTypeBlock(byte type, byte[] res) throws Exception
    {
        // log.debug("Start: readFirstTypeBlock ");

        if (!_sessionStarted)
        {
            throw new Exception("UnstartedSessionAgainsClauer");
        }

        clhandle.outStream.write(this.FUNC_FIND_FIRST_TYPE_BLOCK);
        clhandle.outStream.write(type);

        int err = sDataReader.readByte();

        if (err != 0)
        {
            throw new Exception("ErrorReceivingBlock");
        }

        int nblock = sDataReader.readInt();
        byte[] auxRes = sDataReader.readByteArray(10240);

        for (int i = 0; i < 10240; i++)
        {
            res[i] = auxRes[i];
        }

        // log.debug("Stop: ReadAllTypeObjects ");

        return nblock;
    }

    public int readNextTypeBlock(byte type, byte[] res, int nblock) throws Exception
    {
        // log.debug("Start: readNextTypeBlock ");

        if (!_sessionStarted)
        {
            throw new Exception("UnstartedSessionAgainsClauer");
        }

        clhandle.outStream.write(this.FUNC_FIND_NEXT_TYPE_BLOCK);
        clhandle.outStream.write(type);

        clhandle.outStream.writeInt(Integer.reverseBytes(nblock));

        int err = sDataReader.readByte();

        if (err != 0)
        {
            throw new Exception("ErrorReceivingBlock");
        }

        int nblockAct = sDataReader.readInt();
        if (nblockAct != -1)
        {
            byte[] auxRes = sDataReader.readByteArray(10240);
            for (int i = 0; i < 10240; i++)
            {
                res[i] = auxRes[i];
            }
        }

        // log.debug("Stop: ReadNextTypeBlock ");

        return nblockAct;
    }

    public void closeSession() throws IOException
    {
        // log.debug("Start: closeSession");

        try
        {
            clhandle.outStream.write(this.FUNC_CLOSE_SESSION);
            clhandle.inStream.read();
            clhandle.cleanUp();
        }
        catch (Exception e)
        {
            // Pasando del tema
        }

        // log.debug("End: Closesession");
    }
}

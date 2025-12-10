public class DHEncryptDecrypt 
{
    //using xor
    public static byte[] xorEncrypt(byte[] msg, byte[] skey) 
    {
        byte[] msgbyte = new byte[msg.length];
        for (int i = 0; i < msg.length; i++) 
        {
            msgbyte[i] = (byte) (msg[i] ^ skey[i % skey.length]);
        }
        return msgbyte;
    }

    //decrypting, pass back into encrypt --> same process 
    public static byte[] xorDecrypt(byte[] ciphertext, byte[] skey) 
    {
        return xorEncrypt(ciphertext, skey);
    }

    
    public static String bytesToHex(byte[] d) 
    {
        StringBuilder s = new StringBuilder();
        for (byte b : d) 
        {
            s.append(String.format("%02x", b & 0xff));
        }
        return s.toString();
    }
}

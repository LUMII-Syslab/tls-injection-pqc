package lv.lumii.pqc;

import java.security.PrivateKey;

public class LiboqsPrivateKey
        implements PrivateKey
{
    private String name;
    private byte[] skEncoded;
    private byte[] pkEncoded;
    public LiboqsPrivateKey(String name, byte[] pkEncoded, byte[] skEncoded) {
        this.name = name;
        this.skEncoded = skEncoded;
        this.pkEncoded = pkEncoded;
    }

    @Override
    public String getAlgorithm()
    {
        return name;
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        return this.skEncoded;
    }

    public byte[] pkEncoded() {
        return this.pkEncoded;
    }

    public byte[] skEncoded() {
        return this.skEncoded;
    }
}

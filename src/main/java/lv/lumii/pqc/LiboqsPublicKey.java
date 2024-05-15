package lv.lumii.pqc;

import java.security.PublicKey;

public class LiboqsPublicKey implements PublicKey
{
    private String name;
    private byte[] encoded;
    public LiboqsPublicKey(String name, byte[] encoded) {
        this.name = name;
        this.encoded = encoded;
    }
    @Override
    public String getAlgorithm()
    {
        return name;
    }

    @Override
    public String getFormat()
    {
        return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
        return this.encoded;
    }
}

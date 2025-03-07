package org.bouncycastle.cms;

import org.bouncycastle.util.Selector;

public abstract class RecipientId
    implements Selector
{
    public static final int keyTrans = 0;
    public static final int kek = 1;
    public static final int keyAgree = 2;
    public static final int password = 3;
    public static final int kem = 4;

    private int type;

    protected RecipientId(int type)
    {
        this.type = type;
    }

    /**
     * Return the type code for this recipient ID.
     *
     * @return one of keyTrans, kek, keyAgree, password
     */
    public int getType()
    {
        return type;
    }

    public abstract Object clone();
}

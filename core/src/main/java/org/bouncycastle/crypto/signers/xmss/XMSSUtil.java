package org.bouncycastle.crypto.signers.xmss;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Utils for XMSS implementation.
 */
class XMSSUtil
{

    /**
     * Calculates the logarithm base 2 for a given Integer.
     *
     * @param n Number.
     * @return Logarithm to base 2 of {@code n}.
     */
    public static int log2(int n)
    {
        int log = 0;
        while ((n >>= 1) != 0)
        {
            log++;
        }
        return log;
    }

    /**
     * Convert int/long to n-byte array - RFC 8391 sec. 2.4's toByte(x, y).
     * <p>
     * {@code value} is taken as unsigned, so a {@code sizeInByte} under 8 keeps its low
     * {@code sizeInByte} bytes and one of 8 or more left-pads with zeros. The write is therefore
     * the low min({@code sizeInByte}, 8) bytes placed at the end of the array, which is what
     * {@link Pack#longToBigEndian_Low(long, byte[], int, int)} does; that method is defined for a
     * length of 1..8 only, hence the min.
     *
     * @param value      int/long value.
     * @param sizeInByte Size of byte array in byte, at least 1.
     * @return int/long as big-endian byte array of size {@code sizeInByte}.
     */
    public static byte[] toBytesBigEndian(long value, int sizeInByte)
    {
        byte[] out = new byte[sizeInByte];
        int len = Math.min(sizeInByte, 8);
        Pack.longToBigEndian_Low(value, out, sizeInByte - len, len);
        return out;
    }

    /**
     * Clone a byte array.
     *
     * @param in byte array.
     * @return Copy of byte array.
     */
    public static byte[] cloneArray(byte[] in)
    {
        if (in == null)
        {
            throw new NullPointerException("in == null");
        }
        return Arrays.clone(in);
    }

    /**
     * Return {@code value} once it is confirmed to be {@code size} bytes long, or a freshly
     * allocated all-zero array of that size if {@code value} is null.
     * <p>
     * The optional n-byte fields of the key parameter classes and of the two signature classes
     * are all taken on these terms, and there had been a copy of the check per class - six of
     * them, in two packages, already saying two different things about the same mistake. The
     * wording here is the one the rest of the package uses.
     * </p>
     */
    public static byte[] validateOrAllocate(byte[] value, int size, String name)
    {
        if (value == null)
        {
            return new byte[size];
        }

        return validateSize(value, size, name);
    }

    /**
     * The size check on its own, for a field that is required rather than optional.
     * <p>
     * Absent is not a case here the way it is above: where the caller is importing a value rather
     * than filling in a key it is building, taking the allocation for a null would substitute an
     * all-zero value silently, so null is left to fail as the dereference it is.
     * </p>
     *
     * @param value the value to check.
     * @param size  the size it has to be.
     * @param name  what to call it in a message.
     */
    static byte[] validateSize(byte[] value, int size, String name)
    {
        if (value.length != size)
        {
            throw new IllegalArgumentException("size of " + name + " needs to be equal to size of digest");
        }

        return value;
    }

    /**
     * Clone a 2d byte array.
     *
     * @param in 2d byte array.
     * @return Copy of 2d byte array.
     */
    public static byte[][] cloneArray(byte[][] in)
    {
        if (hasNullPointer(in))
        {
            throw new NullPointerException("in has null pointers");
        }
        return Arrays.clone(in);
    }

    /**
     * Compares two 2d-byte arrays.
     *
     * @param a 2d-byte array 1.
     * @param b 2d-byte array 2.
     * @return true if all values in 2d-byte array are equal false else.
     */
    public static boolean areEqual(byte[][] a, byte[][] b)
    {
        if (hasNullPointer(a) || hasNullPointer(b))
        {
            throw new NullPointerException("a or b == null");
        }
        for (int i = 0; i < a.length; i++)
        {
            if (!Arrays.areEqual(a[i], b[i]))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks whether 2d byte array has null pointers.
     *
     * @param in 2d byte array.
     * @return true if at least one null pointer is found false else.
     */
    public static boolean hasNullPointer(byte[][] in)
    {
        if (in == null)
        {
            return true;
        }
        for (int i = 0; i < in.length; i++)
        {
            if (in[i] == null)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether an index is valid or not.
     *
     * @param height Height of binary tree.
     * @param index  Index to validate.
     * @return true if index is valid false else.
     */
    public static boolean isIndexValid(int height, long index)
    {
        if (index < 0)
        {
            throw new IllegalStateException("index must not be negative");
        }
        return index < (1L << height);
    }

    public static long getTreeIndex(long index, int xmssTreeHeight)
    {
        return index >> xmssTreeHeight;
    }

    public static int getLeafIndex(long index, int xmssTreeHeight)
    {
        return (int)(index & ((1L << xmssTreeHeight) - 1L));
    }

    /**
     * Encode a BDS state, binding it to nothing. Prefer serialize(Object, byte[]): the encoded state
     * carries a checksum, and passing the owning key's public seed ties the state to that key, so a
     * state transplanted between two keys of the same parameters is detected (github #2414).
     */
    public static byte[] serialize(Object obj)
        throws IOException
    {
        return serialize(obj, null);
    }

    /**
     * Encode a BDS state, binding its checksum to the public seed of the key it belongs to.
     *
     * @param obj        the BDS or BDSStateMap to encode.
     * @param publicSeed the owning key's public seed, or null to bind nothing.
     */
    public static byte[] serialize(Object obj, byte[] publicSeed)
        throws IOException
    {
        if (obj instanceof BDS)
        {
            return BDSStateCodec.encode((BDS)obj, publicSeed);
        }
        if (obj instanceof BDSStateMap)
        {
            return BDSStateCodec.encode((BDSStateMap)obj, publicSeed);
        }

        throw new IllegalArgumentException("unsupported BDS state type: "
            + (obj != null ? obj.getClass().getName() : "null"));
    }

    /**
     * Decode a BDS state whose checksum was bound to nothing. Prefer
     * deserialize(byte[], Class, byte[]) - see serialize(Object, byte[]).
     */
    public static Object deserialize(byte[] data, final Class clazz)
        throws IOException, ClassNotFoundException
    {
        return deserialize(data, clazz, null);
    }

    /**
     * Decode a BDS state, checking its checksum against the public seed of the key it belongs to.
     *
     * @param data       the encoded state.
     * @param clazz      BDS or BDSStateMap.
     * @param publicSeed the owning key's public seed, or null if nothing was bound.
     */
    public static Object deserialize(byte[] data, final Class clazz, byte[] publicSeed)
        throws IOException, ClassNotFoundException
    {
        if (clazz == BDS.class || clazz == BDSStateMap.class)
        {
            BDSStateCodec.checkEncodingSize(data);
            if (BDSStateCodec.isBDSStateEncoding(data))
            {
                if (clazz != BDS.class)
                {
                    throw new IOException("unexpected BDS state encoding");
                }
                return BDSStateCodec.decodeBDS(data, publicSeed);
            }
            if (BDSStateCodec.isBDSStateMapEncoding(data))
            {
                if (clazz != BDSStateMap.class)
                {
                    throw new IOException("unexpected BDS state map encoding");
                }
                return BDSStateCodec.decodeBDSStateMap(data, publicSeed);
            }
        }

        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new CheckingStream(clazz, in);

        Object obj = is.readObject();

        if (is.available() != 0)
        {
            throw new IOException("unexpected data found at end of ObjectInputStream");
        }
        // you'd hope this would always succeed!
        if (clazz.isInstance(obj))
        {
            return obj;
        }
        else
        {
            throw new IOException("unexpected class found in ObjectInputStream");
        }
    }

    public static int calculateTau(int index, int height)
    {
        int tau = 0;
        for (int i = 0; i < height; i++)
        {
            if (((index >> i) & 1) == 0)
            {
                tau = i;
                break;
            }
        }
        return tau;
    }

    public static boolean isNewBDSInitNeeded(long globalIndex, int xmssHeight, int layer)
    {
        if (globalIndex == 0)
        {
            return false;
        }
        return (globalIndex % (long)Math.pow((1 << xmssHeight), layer + 1) == 0) ? true : false;
    }

    public static boolean isNewAuthenticationPathNeeded(long globalIndex, int xmssHeight, int layer)
    {
        if (globalIndex == 0)
        {
            return false;
        }
        return ((globalIndex + 1) % (long)Math.pow((1 << xmssHeight), layer) == 0) ? true : false;
    }

    private static class CheckingStream
       extends ObjectInputStream
    {
        private static final Set components = new HashSet();
        /**
         * The names the four serializable state classes carried before this implementation was
         * promoted out of org.bouncycastle.pqc.crypto.xmss, mapped onto the classes here. A
         * private key written by any release before the promotion names them in the Java
         * serialized BDS state it carries, and each of those classes keeps the serialVersionUID
         * and field shape it had there, so resolving the legacy name onto the class here is all
         * that is needed to read one. Nothing writes these names any more - serialize() has
         * emitted the versioned BDSStateCodec form since that codec was introduced.
         */
        private static final Map legacyNames = new HashMap();

        static
        {
            components.add("java.util.TreeMap");
            components.add("java.lang.Integer");
            components.add("java.lang.Number");
            components.add("org.bouncycastle.crypto.signers.xmss.BDS");
            components.add("java.util.ArrayList");
            components.add("org.bouncycastle.crypto.signers.xmss.XMSSNode");
            components.add("[B");
            components.add("java.util.LinkedList");
            components.add("java.util.Stack");
            components.add("java.util.Vector");
            components.add("[Ljava.lang.Object;");
            components.add("org.bouncycastle.crypto.signers.xmss.BDSTreeHash");

            legacyNames.put("org.bouncycastle.pqc.crypto.xmss.BDS", BDS.class);
            legacyNames.put("org.bouncycastle.pqc.crypto.xmss.BDSStateMap", BDSStateMap.class);
            legacyNames.put("org.bouncycastle.pqc.crypto.xmss.BDSTreeHash", BDSTreeHash.class);
            legacyNames.put("org.bouncycastle.pqc.crypto.xmss.XMSSNode", XMSSNode.class);
        }

        private final Class mainClass;
        private boolean found = false;

        CheckingStream(Class mainClass, InputStream in)
            throws IOException
        {
            super(in);

            this.mainClass = mainClass;
        }

        public Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException,
            ClassNotFoundException
        {
            Class legacy = (Class)legacyNames.get(desc.getName());
            String name = (legacy != null) ? legacy.getName() : desc.getName();

            if (!found)
            {
                if (!name.equals(mainClass.getName()))
                {
                    throw new InvalidClassException(
                        "unexpected class: ", desc.getName());
                }
                else
                {
                    found = true;
                }
            }
            else
            {
                if (!components.contains(name))
                {
                    throw new InvalidClassException(
                          "unexpected class: ", desc.getName());
                }
            }
            return (legacy != null) ? legacy : super.resolveClass(desc);
        }
    }
}

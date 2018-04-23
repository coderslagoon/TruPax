package coderslagoon.tclib.container;

import java.lang.reflect.InvocationTargetException;

import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.crypto.XTS;
import coderslagoon.tclib.util.Erasable;
import coderslagoon.tclib.util.TCLibException;

/**
 * TrueCrypt volume encryption or decryption.
 */
public class Volume implements Erasable, Cloneable {
    XTS xts;

    /**
     * Creates a new volume instance.
     * @param mode Mode to either encrypt or decrypt.
     * @param header The header to use. Writing of the header(s) to the
     * beginning and the end of the volume must be handled by the caller itself.
     * @throws TCLibException If any error occurred.
     */
    public Volume(BlockCipher.Mode mode, Header header) throws TCLibException {
        BlockCipher bc1 = null;
        BlockCipher bc2 = null;
        try {
            bc1 = header.blockCipher.getDeclaredConstructor(new Class[0]).newInstance();
            bc2 = header.blockCipher.getDeclaredConstructor(new Class[0]).newInstance();

            bc1.initialize(mode                    , header.keyMaterial.buf, header.keyMaterial.ofs);
            bc2.initialize(BlockCipher.Mode.ENCRYPT, header.keyMaterial.buf, header.keyMaterial.ofs + bc1.keySize());

            this.xts = new XTS(bc1, bc2);
        }
        catch (NoSuchMethodException nsme) {
            throw new TCLibException(nsme);
        }
        catch (InvocationTargetException ite) {
            throw new TCLibException(ite);
        }
        catch (InstantiationException ie) {
            throw new TCLibException(ie);
        }
        catch (IllegalAccessException iae) {
            throw new TCLibException(iae);
        }
        finally {
            if (null == this.xts) {
                if (null != bc1) bc1.erase();
                if (null != bc2) bc2.erase();
            }
        }
    }

    /**
     * @return Size of block of a volume.
     */
    public int blockSize() {
        return XTS.DATA_UNIT_SIZE;
    }

    /**
     * Encrypts or decrypts a block.
     * @param number The block number (0..N-1, N=size of volume in blocks).
     * @param blk Buffer holding the block's data.
     * @param ofs Where the block data starts
     * @throws TCLibException If any error occurred.
     */
    public void processBlock(long number, byte[] blk, int ofs) throws TCLibException {
        this.xts.process(blk, ofs, blockSize(), number, 0);
    }

    /** @see coderslagoon.tclib.util.Erasable#erase() */
    public void erase() {
        this.xts.erase();
    }

    //////////////////////////////////////////////////////////////////////////

    /**
     * To compute the actual size a container must have, meaning the typical.
     * [header][volume][header] format.
     * @param size Size of the volume in blocks.
     * @return Size of the container in blocks.
     */
    public static long sizeToContainerSize(long size) {
        return Header.BLOCK_COUNT + size + Header.BLOCK_COUNT;
    }

    //////////////////////////////////////////////////////////////////////////

    private Volume() {
    }

    /** @see java.lang.Object#clone() */
    public Object clone() {
        Volume result = new Volume();
        result.xts = (XTS)this.xts.clone();
        return result;
    }
}

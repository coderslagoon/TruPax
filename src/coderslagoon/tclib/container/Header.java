package coderslagoon.tclib.container;

import java.lang.reflect.InvocationTargetException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import coderslagoon.baselib.util.BinUtils;
import coderslagoon.baselib.util.BytePtr;
import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.crypto.CRC32;
import coderslagoon.tclib.crypto.Hash;
import coderslagoon.tclib.crypto.PKCS5;
import coderslagoon.tclib.crypto.Rand;
import coderslagoon.tclib.crypto.Registry;
import coderslagoon.tclib.crypto.XTS;
import coderslagoon.tclib.util.Erasable;
import coderslagoon.tclib.util.Key;
import coderslagoon.tclib.util.TCLibException;

/**
 * TrueCrypt header functionality. All what is needed to created and decode a
 * header, no matter if primary, secondary or the hidden candidate.
 */
public class Header implements Erasable {

    /** The default block size (512). This is the most common one, but
     * technically not fixed since some devices do have larger sectors.*/
    public final static int BLOCK_SIZE = 512;
    /** Number of blocks a header occupies. Notice that only the first block
     * truly (no pun intended holds the relevant data is you're dealing with
     * user-mode volume files without hidden headers. */
    public final static int BLOCK_COUNT = 256;
    /** Size of a header in bytes. */
    public final static int SIZE = BLOCK_SIZE * BLOCK_COUNT;
    /** Size of the salt used in a header. */
    public final static int SALT_SIZE = 64;
    /** Maximum size of key material in the header. This covers both of the
     * keys needed for XTS mode. */
    public final static int KEY_MATERIAL_SIZE = 256;
    /** Size of the first reserved section in the header. */
    public final static int RESERVED_SIZE = 16;
    /** Size of the second reserved section in the header. */
    public final static int RESERVED2_SIZE = 124;

    /** Offset in the header where The salt is located.*/
    public final static int OFS_SALT = 0;
    /** Offset in the header where the magic value is located.*/
    public final static int OFS_MAGIC = SALT_SIZE;
    /** Offset in the header where the version is located.*/
    public final static int OFS_VERSION = 68;
    /** Offset in the header where the minimum version is located.*/
    public final static int OFS_MIN_VERSION = 70;
    /** Offset in the header where the CRC32 (over area 256 to 511) is located.*/
    public final static int OFS_CRC32_1 = 72;
    /** Offset in the header where the first reserved section is located.*/
    public final static int OFS_RESERVED = 76;
    /** Offset in the header where the size of a hidden volume is located.*/
    public final static int OFS_HIDDEN_VOLUME_SIZE = 92;
    /** Offset in the header where the size of the volume (in bytes) is located.*/
    public final static int OFS_VOLUME_SIZE = 100;
    /** Offset in the header where the offset to the data is located.*/
    public final static int OFS_DATA_AREA_OFFSET = 108;
    /** Offset in the header where the length of the data (in bytes) is located.*/
    public final static int OFS_DATA_AREA_SIZE = 116;
    /** Offset in the header where the flags are located.*/
    public final static int OFS_FLAGS = 124;
    /** Offset in the header where the second reserved section is located.*/
    public final static int OFS_RESERVED2 = 128;
    /** Offset in the header where the CRC32 (over area 64 to 251) is located.*/
    public final static int OFS_CRC32_2 = 252;
    /** Offset in the header where the actual size of the key (material) is located.*/
    public final static int OFS_KEY_MATERIAL = 256;
    /** Offset in the header where the third reserved section is located. This
     * is already outside of the space which is relevant for volume files
     * with no hidden headers. */
    public final static int OFS_RESERVED3 = 512;
    /** Offset in the header where the hidden volume header might be located.*/
    public final static int OFS_HIDDEN_VOLUME_HEADER = 65536;
    /** Offset in the header where the data area starts. Meaning the actual
     * encrypted blocks of the volume and the end of the header. */
    public final static int OFS_DATA_AREA = SIZE;

    /** Flag bit indicating that the header is used for system (full-disk)
     * encryption. Never set in volume files. */
    public final static int FLAG_SYSTEM_ENCRYPTION = 1;

    ///////////////////////////////////////////////////////////////////////////

    /** To distinguish header types. */
    public static enum Type {
        
        /** For  TrueCrypt volumes. */
        TRUECRYPT("TRUE", false, new Version(3), new Version(0x0600)),
        /** For VeraCrypt volumes. */
        VERACRYPT("VERA", true, new Version(5), new Version(0x010b));
        
        Type(String magic, boolean advanced,
             Version lowestHeader, Version lowestApp) {
            this.magic = magic.getBytes();
            this.advanced = advanced;
            this.lowestHeader = lowestHeader;
            this.lowestApp = lowestApp;
        }
        Map<String, Integer> iterSpec = new HashMap<>(); 

        /** The four character long magic value identifying a volume, given
         * that the key matches, with a certain probability of course. */
        final public byte[] magic;
        
        /** The lowest header version we can deal with. */
        final public Version lowestHeader;
        
        /** The lowest app version we can deal with. */
        final public Version lowestApp;
        
        /** True if the advanced iteration for hash functions should be used. */
        final public boolean advanced;
    }
    
    ///////////////////////////////////////////////////////////////////////////

    /**
     * To check header versions. Useful for both the version and the minimum
     * version in the header. Notice that the header version fields are
     * semantically different: the minimum version is of a class major.minor
     * format, while the actual header version is a simple number.
     */
    public static class Version {

        /**
         * @param value Version value.
         */
        Version(int value) {
            this.value = (short)value;
        }
        /**
         * @param buf Buffer where the version is stored (in the header).
         * @param ofs Offset where the (16bit) version word is located.
         */
        Version(byte[] buf, int ofs) {
            this(BinUtils.readInt16BE(buf, ofs));
        }
        /** The version value. */
        public final short value;
        @Override
        public String toString() {
            return String.format("%d.%d", this.value & 0x0ff, this.value >>> 8);
        }
        /**
         * To check whether this version is compatible to another version. This
         * works for both header and minimum version.
         * @param lowest The lowest version acceptable.
         * @return True if compatible, false if not.
         */
        public boolean compatible(Version lowest) {
            return this.value >= lowest.value;
        }
    }


    ///////////////////////////////////////////////////////////////////////////

    // header fields, populated after decoding or set for writing a new one...

    /** The salt content. */
    public BytePtr salt;
    /** The header version. */
    public Version version;
    /** The minimum TrueCrypt to open the container. */
    public Version minimumVersion;
    /** The first reserved section. All zeros.*/
    public BytePtr reserved;
    /** The size of the hidden volume (if the header is associated with one).*/
    public long sizeofHiddenVolume;
    /** The size of the volume in bytes.*/
    public long sizeofVolume;
    /** The key material zone.*/
    public BytePtr keyMaterial;
    /** Where the data starts (in the volume file).*/
    public long dataAreaOffset;
    /** Size of the data area (in the volume file), in bytes.*/
    public long dataAreaSize;
    /** The header flags.*/
    public int flags;
    /** The second reserved section. All zeros.*/
    public BytePtr reserved2;
    /** The third reserved section. All random.*/
    public BytePtr reserved3;
    /** Where the hidden volume header can be found (ambiguous presence).*/
    public BytePtr hiddenVolumeHeader;

    /** The hash function kind used for encryption. */
    public Class<? extends Hash.Function> hashFunction;
    /** The block cipher kind used for encryption. */
    public Class<? extends BlockCipher> blockCipher;
    
    /** The type of header. */
    Type type;

    ///////////////////////////////////////////////////////////////////////////

    /**
     * To create a new header.
     * @param type The type of the header.
     * @param hashFunction The hash function implementation to use.
     * @param blockCipher The block cipher implementation to use.
     */
    public Header(Type type,
            Class<? extends Hash.Function> hashFunction,
            Class<? extends BlockCipher>   blockCipher) {
        this.type = type;
        this.hashFunction = hashFunction;
        this.blockCipher  = blockCipher;
    }

    /**
     * To parse out a header.
     * @param key The key to decrypt the header.
     * @param buf Buffer containing the header data.
     * @param ofs Where the header data starts in the buffer.
     * @param advanced True to also try advanced iterations of hash functions.
     * @throws TCLibException If any error occurred.
     */
    public Header(Key key, byte[] buf, int ofs, boolean advanced)
            throws TCLibException {
        
        byte[] bbuf = buf.clone();
        for (Type type : Type.values()) {
            if (!advanced && type.advanced)
                continue;
            for (String hash : Registry._hashFunctions.names()) {
                Class<? extends Hash.Function> tryHashFunction = 
                        Registry._hashFunctions.lookup(hash);
                for (String blockCipher : Registry._blockCiphers.names()) {
                    Class<? extends BlockCipher> tryBlockCipher = 
                            Registry._blockCiphers.lookup(blockCipher);
                    try {
                        DecodeResult dres = decode(type,
                                tryBlockCipher.getDeclaredConstructor(new Class[0]).newInstance(),
                                tryBlockCipher.getDeclaredConstructor(new Class[0]).newInstance(),
                                tryHashFunction.getDeclaredConstructor(new Class[0]).newInstance(),
                                key.data(), buf, ofs);
    
                        if (dres == DecodeResult.SUCCESS) {
                            this.hashFunction = tryHashFunction;
                            this.blockCipher  = tryBlockCipher;
                            this.type = type;
                            return;
                        }
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
                    System.arraycopy(bbuf, 0, buf, 0, buf.length);
                }
            }
        }
        throw new NoMatchingAlgorithmException();
    }

    /**
     * Exception to detect if the header decoding failed due to a password
     * mismatch, meaning no algorithm combination yielded proper decryption.
     */
    public static class NoMatchingAlgorithmException extends TCLibException {
        private static final long serialVersionUID = -1332282049420956315L;
        public NoMatchingAlgorithmException() {
            super ("no matching algorithms");
        }
    }

    enum DecodeResult {
        SUCCESS,
        NO_MAGIC,
        BAD_CRC32_1,
        UNEXPECTED_DATA_AREA_OFFSET,
        SYSTEM_ENCRYPTION_NOT_SUPPORTED,
        BAD_CRC32_2,
        UNSUPPORTED_SECTOR_SIZE
    }

    DecodeResult decode(Type type,
            BlockCipher bcipher1, BlockCipher bcipher2,
            Hash.Function hashf,
            byte[] passw, byte[] buf, int ofs) throws TCLibException {
        PKCS5.PBKDF2 kdf = null;
        XTS xts = null;
        CRC32 crc = null;

        byte[] kbuf = null;

        try {
            kdf = new PKCS5.PBKDF2(hashf);

            this.salt = new BytePtr(buf, ofs + OFS_SALT, SALT_SIZE);

            kbuf = kdf.deriveKey(
                    passw,
                    this.salt.extract(),
                    hashf.recommededHMACIterations(type.advanced),
                    bcipher1.keySize() +
                    bcipher2.keySize());

            bcipher1.initialize(BlockCipher.Mode.DECRYPT, kbuf, 0);
            bcipher2.initialize(BlockCipher.Mode.ENCRYPT, kbuf, bcipher2.keySize());

            xts = new XTS(bcipher1, bcipher2);

            xts.process(buf, ofs + SALT_SIZE, BLOCK_SIZE - SALT_SIZE, 0L, 0);

            //BinUtils.hexDump(buf, System.out, 48, 4);

            if (!BinUtils.arraysEquals(buf, ofs + OFS_MAGIC, type.magic, 0, type.magic.length)) {
                return DecodeResult.NO_MAGIC;
            }

            this.version        = new Version(buf, ofs + OFS_VERSION);
            this.minimumVersion = new Version(buf, ofs + OFS_MIN_VERSION);

            crc = new CRC32();
            crc.update(buf, ofs + OFS_KEY_MATERIAL, KEY_MATERIAL_SIZE);
            if (crc.get() != BinUtils.readInt32BE(buf, ofs + OFS_CRC32_1)) {
                return DecodeResult.BAD_CRC32_1;
            }

            this.reserved           = new BytePtr(buf, ofs + OFS_RESERVED, RESERVED_SIZE);
            this.sizeofHiddenVolume = BinUtils.readInt64BE(buf, ofs + OFS_HIDDEN_VOLUME_SIZE);
            this.sizeofVolume       = BinUtils.readInt64BE(buf, ofs + OFS_VOLUME_SIZE);

            this.dataAreaOffset = BinUtils.readInt64BE(buf, ofs + OFS_DATA_AREA_OFFSET);
            if (OFS_DATA_AREA != this.dataAreaOffset) {
                return DecodeResult.UNEXPECTED_DATA_AREA_OFFSET;
            }
            this.dataAreaSize = BinUtils.readInt64BE(buf, ofs + OFS_DATA_AREA_SIZE);

            this.flags = BinUtils.readInt32BE(buf, ofs + OFS_FLAGS);
            if (0 != (FLAG_SYSTEM_ENCRYPTION & this.flags)) {
                return DecodeResult.SYSTEM_ENCRYPTION_NOT_SUPPORTED;
            }

            if (type == Type.VERACRYPT) {
                int sectorSize = BinUtils.readInt32BE(buf, ofs + OFS_RESERVED2);
                if (sectorSize != BLOCK_SIZE)
                    return DecodeResult.UNSUPPORTED_SECTOR_SIZE;
            }
            
            this.reserved2 = new BytePtr(buf, ofs + OFS_RESERVED2, RESERVED2_SIZE);

            crc.reset();
            crc.update(buf, ofs + SALT_SIZE, OFS_CRC32_2 - SALT_SIZE);
            if (crc.get() != BinUtils.readInt32BE(buf, ofs + OFS_CRC32_2)) {
                return DecodeResult.BAD_CRC32_2;
            }

            this.keyMaterial = new BytePtr(buf, ofs + OFS_KEY_MATERIAL, KEY_MATERIAL_SIZE);

            this.reserved3          = new BytePtr(buf, ofs + OFS_RESERVED3, 65024);
            this.hiddenVolumeHeader = new BytePtr(buf, ofs + OFS_HIDDEN_VOLUME_HEADER, 65536);

            return DecodeResult.SUCCESS;
        }
        finally {
            if (null != kbuf) Arrays.fill(kbuf, (byte)0);

            bcipher1.erase();
            bcipher2.erase();
            hashf   .erase();
            if (null != kdf) kdf.erase();
            if (null != xts) xts.erase();
            if (null != crc) crc.erase();
        }
    }

    @Override
    public void erase() {
        eraseKeyMaterial();
        if (null != this.reserved          ) { this.reserved          .clear(); this.reserved           = null; }
        if (null != this.reserved2         ) { this.reserved2         .clear(); this.reserved2          = null; }
        if (null != this.reserved3         ) { this.reserved3         .clear(); this.reserved3          = null; }
        if (null != this.hiddenVolumeHeader) { this.hiddenVolumeHeader.clear(); this.hiddenVolumeHeader = null; }
    }

    private void eraseKeyMaterial() {
        this.keyMaterial.clear();
        this.keyMaterial = null;
    }

    static DateFormat _dfmt;
    static {
        _dfmt = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss.SSS");
        _dfmt.setTimeZone(TimeZone.getTimeZone("GMT")); // helps, sort of...
    }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();

        result.append("salt       : " + BinUtils.bytesToHexString(this.salt) + "\n")
              .append("version    : " + this.version + "\n")
              .append("min-version: " + this.minimumVersion + "\n")
              .append("volume-size: " + this.sizeofVolume + "\n")
              .append("data-ofs   : " + this.dataAreaOffset + "\n")
              .append("data-size  : " + this.dataAreaSize + "\n")
              .append("hashfct-clz: " + this.hashFunction.getSimpleName() + "\n")
              .append("bcipher-clz: " + this.blockCipher.getSimpleName() + "\n");

        return result.toString();
    }

    Rand rnd;
    Rand rnd() {
        if (null == this.rnd) {
            this.rnd = Rand.wrap(Rand.secure());
        }
        return this.rnd;
    }

    /**
     * Encode a header.
     * @param passw The key material to use for encryption.
     * @return The encrypted header material.
     * @throws TCLibException If any error occurred.
     */
    public byte[] encode(byte[] passw) throws TCLibException {
        if (null == this.version ||
            null == this.minimumVersion) {
            throw new TCLibException();
        }

        byte[] kbuf = null;
        byte[] result = new byte[SIZE];

        PKCS5.PBKDF2 kdf = null;
        XTS xts = null;
        CRC32 crc = null;
        Hash.Function hashf = null;
        BlockCipher bcipher1 = null;
        BlockCipher bcipher2 = null;

        try {
            System.arraycopy(this.salt.buf, this.salt.ofs, result, OFS_SALT, SALT_SIZE);

            System.arraycopy(this.type.magic, 0, result, OFS_MAGIC,
                             this.type.magic.length);

            // (don't write the reserved areas, they're all zero anyway)
            BinUtils.writeInt16BE(this.version.value       , result, OFS_VERSION);
            BinUtils.writeInt16BE(this.minimumVersion.value, result, OFS_MIN_VERSION);
            BinUtils.writeInt64BE(this.sizeofHiddenVolume  , result, OFS_HIDDEN_VOLUME_SIZE);
            BinUtils.writeInt64BE(this.sizeofVolume        , result, OFS_VOLUME_SIZE);
            BinUtils.writeInt64BE(this.dataAreaOffset      , result, OFS_DATA_AREA_OFFSET);
            BinUtils.writeInt64BE(this.dataAreaSize        , result, OFS_DATA_AREA_SIZE);
            BinUtils.writeInt32BE(this.flags               , result, OFS_FLAGS);
            
            if (this.type == Type.VERACRYPT)
                BinUtils.writeInt32BE(BLOCK_SIZE, result, OFS_RESERVED2);

            System.arraycopy(this.keyMaterial.buf,
                             this.keyMaterial.ofs,
                             result,
                             OFS_KEY_MATERIAL,
                             this.keyMaterial.len);

            crc = new CRC32(); // it's important that we do this one first!
            crc.update(result, OFS_KEY_MATERIAL, KEY_MATERIAL_SIZE);
            BinUtils.writeInt32BE(crc.get(), result, OFS_CRC32_1);

            crc.reset();
            crc.update(result, SALT_SIZE, OFS_CRC32_2 - SALT_SIZE);
            BinUtils.writeInt32BE(crc.get(), result, OFS_CRC32_2);

            hashf = this.hashFunction.getDeclaredConstructor(new Class[0]).newInstance();
            bcipher1 = this.blockCipher.getDeclaredConstructor(new Class[0]).newInstance();
            bcipher2 = this.blockCipher.getDeclaredConstructor(new Class[0]).newInstance();

            kdf = new PKCS5.PBKDF2(hashf);

            kbuf = kdf.deriveKey(
                    passw,
                    this.salt.extract(),
                    hashf.recommededHMACIterations(this.type.advanced),
                    bcipher1.keySize() +
                    bcipher2.keySize());

            bcipher1.initialize(BlockCipher.Mode.ENCRYPT, kbuf, 0);
            bcipher2.initialize(BlockCipher.Mode.ENCRYPT, kbuf, bcipher2.keySize());

            xts = new XTS(bcipher1, bcipher2);

            xts.process(result, SALT_SIZE, BLOCK_SIZE - SALT_SIZE, 0L, 0);

            // the rest is all random data, either reused or new...
            final int rsvsz3 = OFS_HIDDEN_VOLUME_HEADER - OFS_RESERVED3;
            if (null == this.reserved3) {
                rnd().make(result, OFS_RESERVED3, rsvsz3);
            }
            else {
                System.arraycopy(this.reserved3.buf,
                                 this.reserved3.ofs,
                                 result,
                                 OFS_RESERVED3,
                                 rsvsz3);
            }
            final int hvolsz = SIZE - OFS_HIDDEN_VOLUME_HEADER;
            if (null == this.hiddenVolumeHeader) {
                rnd().make(result, OFS_HIDDEN_VOLUME_HEADER, SIZE - OFS_HIDDEN_VOLUME_HEADER);
            }
            else {
                System.arraycopy(this.hiddenVolumeHeader.buf,
                                 this.hiddenVolumeHeader.ofs,
                                 result,
                                 OFS_HIDDEN_VOLUME_HEADER,
                                 hvolsz);
            }
        }
        catch (Throwable err) {
            Arrays.fill(result, (byte)0);
            throw new TCLibException(err);
        }
        finally {
            if (null != kdf     ) kdf     .erase();
            if (null != xts     ) xts     .erase();
            if (null != crc     ) crc     .erase();
            if (null != hashf   ) hashf   .erase();
            if (null != bcipher1) bcipher1.erase();
            if (null != bcipher2) bcipher2.erase();
            if (null != kbuf    ) Arrays.fill(kbuf, (byte)0);
        }

        return result;
    }

    /**
     * Generates a salt value for consecutive header creation, meaning you can
     * keep the instance and then create a backup header.
     * @param rnd The random generator to use.
     * @throws TCLibException If any error occurred.
     */
    public void generateSalt(Rand rnd) throws TCLibException {
        this.salt = new BytePtr(new byte[SALT_SIZE]);
        (null == rnd ? rnd() : rnd).make(this.salt);
    }

    /**
     * Generates key material for consecutive header creation, meaning you can
     * keep the instance and then create a backup header.
     * @param rnd The random generator to use.
     * @throws TCLibException If any error occurred.
     */
    public void generateKeyMaterial(Rand rnd) throws TCLibException {
        if (null == this.hashFunction) {
            throw new TCLibException("no hash function given");
        }
        if (null == this.blockCipher) {
            throw new TCLibException("no block cipher given");
        }

        if (null != this.keyMaterial) {
            eraseKeyMaterial();
        }

        if (null == rnd) {
            rnd = rnd();
        }

        BlockCipher bcipher = null;

        try {
            bcipher = this.blockCipher.getDeclaredConstructor(new Class[0]).newInstance();
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

        try {
            int kmsz = bcipher.keySize() << 1;

            if (KEY_MATERIAL_SIZE < kmsz) {
                throw new TCLibException();
            }

            this.keyMaterial = new BytePtr(new byte[KEY_MATERIAL_SIZE]);

            // NOTE: the TC documentation says nothing about the unused space,
            //       so we leave it to be zero, filling it with random data
            //       would be another (better?) option...
            rnd.make(this.keyMaterial.buf,
                     this.keyMaterial.ofs,
                     kmsz);
        }
        finally {
            bcipher.erase();
        }
    }
}

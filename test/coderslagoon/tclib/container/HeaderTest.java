package coderslagoon.tclib.container;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;

import org.junit.Before;
import org.junit.Test;

import coderslagoon.baselib.io.IOUtils;
import coderslagoon.baselib.util.BinUtils;
import coderslagoon.baselib.util.BytePtr;
import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.container.Header.Type;
import coderslagoon.tclib.crypto.AES256;
import coderslagoon.tclib.crypto.RIPEMD160;
import coderslagoon.tclib.crypto.Rand;
import coderslagoon.tclib.crypto.Registry;
import coderslagoon.tclib.crypto.SHA512;
import coderslagoon.tclib.util.Key;
import coderslagoon.tclib.util.TCLibException;

public class HeaderTest {

    @Before
    public void setUp() throws Exception {
        Registry.setup(false);
    }
    
    @Test
    public void test5GB_AES_RIPEMD160() throws IOException {

        // (block data taken from a real 5GB volume)
        InputStream ins = getClass().getResourceAsStream("resources/5gb_aes_ripemd160_header");
        byte[] hdata = IOUtils.readStreamBytes(ins);
        byte[] hdata_orig = hdata.clone();

        assertTrue(Header.SIZE == hdata.length);

        try {
            Header hdr = new Header(new Key.ByteArray(
                    "test12345".getBytes()), hdata, 0, false);

            assertTrue(4      == hdr.version.value);
            assertTrue(0x0600 == hdr.minimumVersion.value);
            assertEquals("4.0", hdr.version.toString());
            assertTrue(hdr.minimumVersion.compatible(Header.Type.TRUECRYPT.lowestApp));
            assertTrue(hdr.version.compatible(Header.Type.TRUECRYPT.lowestHeader));
            assertFalse(hdr.version.compatible(new Header.Version(5)));

            final long TC_5GB = 5L * 1024L * 1024L * 1024L - Header.SIZE * 2;

            assertTrue(TC_5GB == hdr.dataAreaSize);
            assertTrue(TC_5GB == hdr.sizeofVolume);

            assertTrue(Header.SIZE == hdr.dataAreaOffset);

            // NOTE: reserved3 is pure random so we can't really check it
            for (BytePtr bp : new BytePtr[] { hdr.reserved,
                                              hdr.reserved2 }) {
                for (int i = 0; i < bp.len; i++) {
                    assertTrue(0 == bp.at(i));
                }
            }

            assertTrue(hdr.blockCipher .equals(AES256   .class));
            assertTrue(hdr.hashFunction.equals(RIPEMD160.class));

            byte[] enc = hdr.encode("test12345".getBytes());
            assertTrue(Header.SIZE == enc.length);
            assertTrue(BinUtils.arraysEquals(enc, hdata_orig));
            assertTrue(hdr.toString().contains("volume-size"));

            hdr.reserved  =
            hdr.reserved2 =
            hdr.reserved3 =
            hdr.hiddenVolumeHeader = null;
            enc = hdr.encode("test12345".getBytes());
            assertTrue(Header.SIZE == enc.length);
            assertFalse(BinUtils.arraysEquals(enc, hdata_orig));

            hdr.erase();
        }
        catch (TCLibException tle) {
            tle.printStackTrace(System.err);
            System.err.print(tle.getMessage());
            fail();
        }
    }
    
    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void test5MB_AES_SHA512() throws IOException {

        InputStream ins = getClass().getResourceAsStream("resources/5mb_aes_sha512_header");
        byte[] hdata = IOUtils.readStreamBytes(ins);

        assertTrue(Header.SIZE == hdata.length);
        final byte[] passw = "123".getBytes(); 

        try {
            Header hdr = new Header(new Key.ByteArray(passw.clone()), hdata, 0, false);

            assertEquals(5, hdr.version.value);
            assertEquals(0x0700, hdr.minimumVersion.value);
            assertEquals("5.0", hdr.version.toString());
            assertTrue(hdr.minimumVersion.compatible(Header.Type.TRUECRYPT.lowestApp));
            assertTrue(hdr.version.compatible(Header.Type.TRUECRYPT.lowestHeader));
            assertFalse(hdr.version.compatible(new Header.Version(6)));

            final long TC_5MB = 5L * 1024L * 1024L - Header.SIZE * 2;

            assertEquals(TC_5MB, hdr.dataAreaSize);
            assertEquals(TC_5MB, hdr.sizeofVolume);

            assertEquals(Header.SIZE, hdr.dataAreaOffset);

            assertEquals(AES256.class, hdr.blockCipher);
            assertEquals(SHA512.class, hdr.hashFunction);

            hdr.erase();
        }
        catch (TCLibException tle) {
            tle.printStackTrace(System.err);
            System.err.print(tle.getMessage());
            fail();
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void test20MB_AES_SHA512_vera() throws IOException {

        InputStream ins = getClass().getResourceAsStream("resources/20mb_aes_sha512_header_VERA");
        byte[] hdata = IOUtils.readStreamBytes(ins);

        assertTrue(Header.SIZE == hdata.length);
        final byte[] passw = "abc123".getBytes(); 

        try {
            Header hdr = new Header(new Key.ByteArray(passw.clone()), hdata, 0, true);

            assertEquals(5, hdr.version.value);
            assertEquals(0x010b, hdr.minimumVersion.value);
            assertEquals("5.0", hdr.version.toString());
            assertTrue(hdr.minimumVersion.compatible(Header.Type.VERACRYPT.lowestApp));
            assertTrue(hdr.version.compatible(Header.Type.VERACRYPT.lowestHeader));
            assertFalse(hdr.version.compatible(new Header.Version(6)));

            final long HC_20MB = 20L * 1024 * 1024 - Header.SIZE * 2;

            assertEquals(HC_20MB, hdr.dataAreaSize);
            assertEquals(HC_20MB, hdr.sizeofVolume);

            assertEquals(Header.SIZE, hdr.dataAreaOffset);

            assertEquals(AES256.class, hdr.blockCipher);
            assertEquals(SHA512.class, hdr.hashFunction);

            hdr.erase();
        }
        catch (TCLibException tle) {
            tle.printStackTrace(System.err);
            System.err.print(tle.getMessage());
            fail();
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    static class DummyRand extends Rand {
        long bytesTotal;
        int counter;
        public void make(byte[] buf, int ofs, int len) {
            for (int end = ofs + len; ofs < end; ofs++) {
                buf[ofs] = (byte)this.counter++;
            }
            this.bytesTotal += len;
        }
        public void test() throws Throwable { }
        public void erase() { }
    }

    @Test
    public void testKeyMaking() throws Exception {
        Header hdr = new Header(Type.TRUECRYPT, RIPEMD160.class, AES256.class);

        hdr.generateKeyMaterial(null);

        int keysSize = AES256.class.getDeclaredConstructor(new Class[0]).newInstance().keySize() << 1;

        int sum = 0;  // very, very unlikely that the whole key will be all zero
        for (int i = 0; i < keysSize; i++) {
            sum += hdr.keyMaterial.at(i) & 0xff;
        }
        assertTrue(0 < sum);
        for (int i = keysSize; i < Header.KEY_MATERIAL_SIZE; i++) {
            assertTrue(0 == hdr.keyMaterial.at(i));
        }

        DummyRand drnd = new DummyRand();

        hdr.generateKeyMaterial(drnd);

        assertTrue(drnd.bytesTotal == keysSize);

        for (int i = 0; i < keysSize; i++) {
            assertTrue((byte)i == hdr.keyMaterial.at(i));
        }
        for (int i = keysSize; i < Header.KEY_MATERIAL_SIZE; i++) {
            assertTrue(0 == hdr.keyMaterial.at(i));
        }
    }
}

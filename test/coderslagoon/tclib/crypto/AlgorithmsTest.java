package coderslagoon.tclib.crypto;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import coderslagoon.tclib.util.Testable;

public class AlgorithmsTest {
    @SuppressWarnings("unchecked")
    @Test
    public void test0() throws Throwable {
        for (Class<Testable> clz : new Class[] {
                CRC32       .class,
                AES256      .class,
                RIPEMD160   .class,
                SHA512      .class,
                HMAC        .class,
                PKCS5.PBKDF2.class,
                XTS         .class,
        }) {
            Testable tst = clz.getDeclaredConstructor(new Class[0]).newInstance();
            tst.test();
            if (tst instanceof Algorithm) {
                String name = ((Algorithm)tst).name();
                assertTrue(null == name ^ (null != name && 0 < name.length()));
            }
        }
    }

    @Test
    public void testPBKDF2Performance() {
        
        for (boolean advanced : new Boolean[] { false, true }) 
        for (Hash.Function hf : new Hash.Function[] { 
                new RIPEMD160(), 
                new SHA512() }) {
            
            PKCS5.PBKDF2 pbkdf2 = new PKCS5.PBKDF2(hf);
            long delta, start = System.currentTimeMillis();
            long setups = 0;
            for (;5000 > (delta = System.currentTimeMillis() - start); 
                 setups++) {
                assertTrue(48 == pbkdf2.deriveKey(
                        "password".getBytes(), "salty\r\n".getBytes(),
                        hf.recommededHMACIterations(advanced), 48).length);
            }
            assertTrue(0 < setups);
            long rate = (setups * 1000000) / delta;
            System.out.printf("%s(%s): %.2f setups/second\n", hf.name(),
                    advanced, rate/1000.0);
        }
    }
}

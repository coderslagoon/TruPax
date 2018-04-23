package coderslagoon.trupax.test.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.Set;

import org.junit.After;


import coderslagoon.baselib.io.BlockDevice;
import coderslagoon.baselib.io.BlockDeviceImpl;
import coderslagoon.baselib.io.IOUtils;
import coderslagoon.baselib.util.Combo;
import coderslagoon.baselib.util.MiscUtils;
import coderslagoon.baselib.util.VarInt;
import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.container.Volume;
import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.crypto.Registry;
import coderslagoon.tclib.util.Key;
import coderslagoon.tclib.util.Password;
import coderslagoon.test.util.FileNameMaker;
import coderslagoon.test.util.FilePathWalker;
import coderslagoon.test.util.TestError;
import coderslagoon.test.util.TestUtils;
import coderslagoon.trupax.lib.Reader;
import coderslagoon.trupax.lib.UDFReader;
import coderslagoon.trupax.lib.io.filesystem.udf.Browser;
import coderslagoon.trupax.tc.TCReader;

public class Verifier {
    File        tmpDir;
    PrintStream log;
    PrintStream err;
    List<File>  roots = new ArrayList<>();
    Creator     creator;

    ///////////////////////////////////////////////////////////////////////////

    public Verifier(Long seed, File tmpDir, PrintStream log, PrintStream err,
                    FileNameMaker fnmk, Class<Creator> cclazz) throws IOException {
        this.log = log;
        this.err = err;
        this.tmpDir = null == tmpDir ? new File(
            // NOTE: OSX has insanely long temporary paths, this screws up test
            //       cases right, which admittedly should be a bit more flexible
            MiscUtils.underOSX() ? "/tmp" : System.getProperty("java.io.tmpdir")) : tmpDir;
        try {
            this.creator = (null == cclazz ? DefaultCreator.class : cclazz).getDeclaredConstructor(new Class[0]).newInstance();
        }
        catch (Exception e) {
            throw new IOException(e.getLocalizedMessage());
        }
        fnmk = new FileNameMaker.Filtered(fnmk) {
            final Set<String> illegalFilenames = new HashSet<>(); {
                for (String ifn : new String[] {
                        "prn", "con", "nul", "aux"
                }) {
                    this.illegalFilenames.add(ifn);
                }
            }
            protected boolean filter(String name) {
                return this.illegalFilenames.contains(name.toLowerCase());
            }
        };
        this.creator.ctor(log, err, seed, fnmk);
    }

    ///////////////////////////////////////////////////////////////////////////

    @After
    public boolean cleanUp() {
        boolean result = true;
        for (File root : this.roots) {
            result |= TestUtils.removeDir(root, true);
        }
        this.roots.clear();
        return result;
    }

    ///////////////////////////////////////////////////////////////////////////

    public interface Setup {
        String[] basePath();
        boolean usingAbsolutePath();
        int  maxFiles();
        int  maxPathLen();
        int  minSubDirsPerDir();
        int  maxSubDirsPerDir();
        int  minFilesPerDir();
        int  maxFilesPerDir();
        long minFileSize();
        long maxFileSize();
        int  minFileNameLen();
        int  maxFileNameLen();
        long maxBytes();
    }

    ///////////////////////////////////////////////////////////////////////////

    public static abstract class Creator {
        protected PrintStream   log;
        protected PrintStream   err;
        protected Random        rnd;
        protected FileNameMaker fnmk;

        public void ctor(PrintStream log, PrintStream err, Long seed, FileNameMaker fnmk) {
            this.log  = log;
            this.err  = err;
            this.fnmk = fnmk;
            this.rnd  = new Random(null == seed ? 0x0123456789abcdefL : seed);
        }
        public static class Result {
            public int  dirs;
            public int  files;
            public long bytes;
        }
        public abstract int create(File dir, Setup setup, Result res) throws IOException;
    }

    ///////////////////////////////////////////////////////////////////////////

    static class DefaultCreator extends Creator {
        long  bytesLeft;
        int   filesLeft;
        int   pathDepth;
        int   basePathDelta;
        Setup setup;

        public int create(File dir, Setup setup, Result res) throws IOException {
            this.setup = setup;

            this.bytesLeft = setup.maxBytes();
            this.filesLeft = setup.maxFiles();

            this.basePathDelta = setup.usingAbsolutePath() ?
                                 0 : dir.getAbsolutePath().length();

            return createInternal(dir, res);
        }

        int createInternal(File dir, Result res) throws IOException {
            this.pathDepth++;

            int maxObjNameLen = this.setup.maxPathLen() - (dir.getAbsolutePath().length() - this.basePathDelta);
            if (this.setup.minFileNameLen() > maxObjNameLen) {
                final int up = this.rnd.nextInt(this.pathDepth);
                this.log.printf("path too long, going up %d level(s)...\n", up);
                return up;
            }
            maxObjNameLen = Math.min(this.setup.maxFileNameLen(), maxObjNameLen);

            int fcount = this.rnd.nextInt(this.setup.maxFilesPerDir  () - this.setup.minFilesPerDir()) +
                                                                          this.setup.minFilesPerDir();
            int dcount = this.rnd.nextInt(this.setup.maxSubDirsPerDir() - this.setup.minSubDirsPerDir()) +
                                                                          this.setup.minSubDirsPerDir();

            for (int createDirs = 0; createDirs < 2; createDirs++) {
                int ocount = 0 == createDirs ? fcount : dcount;

                for (int i = 0; i < ocount; i++) {
                    File obj = null;
                    final int maxRetries = fcount + dcount;
                    for (int j = 0; j < maxRetries; j++) {
                        int objNameLen = this.setup.minFileNameLen();
                        objNameLen += this.rnd.nextInt(maxObjNameLen - objNameLen + 1);
                        String objName = this.fnmk.make(objNameLen);
                        obj = new File(dir, objName);
                        if (!obj.exists()) {
                            break;
                        }
                        this.err.printf("name collision (%s), retrying...\n", obj.getAbsolutePath());
                        obj = null;
                    }
                    if (null == obj) {
                        String msg = String.format("too many collisions, giving up after %d retries", maxRetries);
                        this.err.println(msg);
                        throw new IOException(msg);
                    }

                    if (0 == createDirs) {
                        long flen = this.setup.minFileSize();
                        flen += Math.abs(this.rnd.nextLong()) % Math.max(1L, this.setup.maxFileSize() - flen);
                        flen = Math.min(this.bytesLeft, flen);

                        this.bytesLeft -= flen;

                        this.log.printf("creating file '%s' (%d bytes, %d left) ...\n",
                                obj.getAbsolutePath(),
                                flen,
                                this.bytesLeft);
                        TestUtils.fillFile123(obj, flen);
                        res.files++;
                        res.bytes += flen;

                        if (0 == this.bytesLeft) {
                            this.log.println("reached total data limit");
                            return -1;
                        }
                        if (--this.filesLeft == 0) {
                            this.log.println("reached total file limit");
                            return -1;
                        }
                    }
                    else {
                        if (obj.mkdir()) {
                            res.dirs++;
                            this.log.printf("created directory '%s', entering it...\n", obj.getAbsolutePath());
                            int cres = createInternal(obj, res);
                            this.pathDepth--;
                            if (-1 == cres) {
                                return -1;
                            }
                            else if (-2 == cres || cres == 1) {
                                ocount++;
                            }
                            else if (cres > 1) {
                                cres--;
                                return cres;
                            }
                        }
                        else {
                            String msg = String.format("cannot create directory '%s'",
                                                       obj.getAbsolutePath());
                            this.err.println(msg);
                            throw new IOException(msg);
                        }
                    }
                }
            }
            return -2;
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    public File makeDirsAndFiles(Setup setup) throws IOException {
        return makeDirsAndFiles(setup, new Creator.Result());
    }

    public File makeDirsAndFiles(Setup setup, Creator.Result cr) throws IOException {
        File dir = new File(this.tmpDir, String.format("verifier%d",
                System.currentTimeMillis()));

        File result = dir;

        if (dir.exists() && !TestUtils.removeDir(dir, true)) {
            this.err.printf("cannot get rid of old directory structure '%s'\n", dir);
            return null;
        }

        for (String bp : setup.basePath()) {
            dir = new File(dir, bp);
        }

        if (!dir.mkdirs()) {
            this.err.printf("cannot create base directory structure '%s'\n", dir);
            return null;
        }

        int cres = this.creator.create(dir, setup, cr);
        if (0 > cres) {
            this.roots.add(result);
            return result;
        }
        this.err.printf("creation failed (%d), could%s get rid of structure\n",
                cres, TestUtils.removeDir(result, true) ? "" : " NOT");
        return null;
    }

    ///////////////////////////////////////////////////////////////////////////

    public File newVolumeFile() {
        return newVolumeFile("");
    }
    
    public File newVolumeFile(String ext) {
        File result = new File(this.tmpDir, String.format("verifier_volumes"));
        if (!result.exists() && !result.mkdirs()) {
            return null;
        }
        result = new File(result, String.format("vol_%d_%08x%s",
                System.currentTimeMillis(),
                new SecureRandom().nextInt(),
                ext));

        if (!result.exists() || result.delete()) {
            return result;
        }
        return null;
    }

    ///////////////////////////////////////////////////////////////////////////

    @FunctionalInterface
    public interface Matcher {
        void match(final File rootDir, File volume, int blockSz, Key key,
                   String hashFunction, String blockCipher,
                   final Setup setup) throws Exception;
    }

    ///////////////////////////////////////////////////////////////////////////

    public Matcher browserMatcher() { 
        return (rootDir, volume, blockSz, key, hashFunction, blockCipher, setup) -> {
            final String FOUND_EXT = ".found";

            final List<String> dirPaths = new ArrayList<>();

            TCBrowser tcb = new TCBrowser(volume, new Browser.Listener() {
                public OutputStream onFile(String name, long time, long length) throws IOException {
                    File fl = nameToObj(name, false);

                    fileTimeCheck(fl, time);

                    final long flen = fl.length();

                    if (flen != length) {
                        throw new IOException(String.format(
                            "length mismatch %d!=%d", length, flen));
                    }

                    return new OutputStream() {
                        long len = 0L;
                        public void write(int b) throws IOException {
                            if ((byte)b == (byte)this.len) {
                                this.len++;
                                return;
                            }
                            throw new IOException(String.format(
                                    "mismatch at position %d", this.len));
                        }
                        public void close() throws IOException {
                            if (this.len != flen) {
                                throw new IOException(String.format(
                                    "read length mismatch %d!=%d", flen, this.len));
                            }
                        }
                    };
                }
                public void onDirectory(String path, long time) throws IOException {
                    File dir = nameToObj(path, true);

                    fileTimeCheck(dir, time);

                    dirPaths.add(nameToObj(path, true).getAbsolutePath());
                }
                File nameToObj(String name, boolean isDir) throws IOException {
                    File obj = new File(setup.usingAbsolutePath() ?
                            IOUtils.getRoot(rootDir) : rootDir.getParentFile(),
                            name);

                    if (!obj.exists()) {
                        throw new IOException(String.format(
                                "missing %s %s",
                                isDir ? "directory" : "file",
                                obj.getAbsolutePath()));
                    }

                    if (!isDir) {
                        File fnd = new File(obj.getAbsolutePath() + FOUND_EXT);
                        if (!obj.renameTo(fnd)) {
                            throw new IOException(String.format(
                                    "cannot rename %s to %s",
                                    obj.getAbsolutePath(),
                                    fnd.getAbsolutePath()));
                        }
                        obj = fnd;
                    }

                    return obj;
                }
            }, blockSz, key);

            if (tcb.tcr.nameOfBlockCipher().equals(blockCipher)) {
                throw new IOException("block cipher name mismatch");
            }
            if (tcb.tcr.nameOfHashFunction().equals(hashFunction)) {
                throw new IOException("hash function name mismatch");
            }

            tcb.exec();
            tcb.close();

            FilePathWalker fpw = new FilePathWalker() {
                public boolean onObject(File obj) {
                    if (obj.isDirectory()) {
                        if (dirPaths.contains(obj.getAbsolutePath())) {
                            return true;
                        }
                        Verifier.this.err.printf("unregistered directory '%s'", obj.getAbsolutePath());
                        return false;
                    }
                    if (obj.getName().endsWith(FOUND_EXT)) {
                        return true;
                    }
                    Verifier.this.err.printf("unregistered file '%s'", obj.getAbsolutePath());
                    return false;
                }
            };

            if (!fpw.walk(rootDir)) {
                throw new IOException("walking failed");
            }
        };
    }

    ///////////////////////////////////////////////////////////////////////////

    public Matcher readerMatcher() {
        return (rootDir, volume, blockSz, key, hashFunction, blockCipher, setup) -> {
            RandomAccessFile raf = new RandomAccessFile(volume, "r");
            BlockDevice bdev = new BlockDeviceImpl.FileBlockDevice(raf, 512, -1L, true, false);
            TCReader tcr = new TCReader(bdev, key, false, false);
            Properties props = new Properties();
            UDFReader ur = new UDFReader(tcr, props);
            final VarInt nofiles  = new VarInt(-1);
            final VarInt nodirs   = new VarInt(-1);
            final File extractDir = TestUtils.createTempDir("readermatcher");
            ur.extract(extractDir, new Reader.Progress2() {
                File    fl;
                Long    size;
                Long    tstamp;
                public Result onMounting(int numOfObjects) {
                    return Result.OK;
                }
                public Result onMount(int numOfFiles, int numOfDirs) {
                    nofiles.v = numOfFiles;
                    nodirs .v = numOfDirs;
                    return Result.OK;
                }
                public Result onDirectory(File dir, long size, Long tstamp) {
                    return onObject(dir, size, tstamp);
                }
                public Result onFile(File fl, long size, Long tstamp) {
                    return onObject(fl, size, tstamp);
                }
                private Result onObject(File fl, long size, Long tstamp) {
                    this.fl     = fl;
                    this.size   = size;
                    this.tstamp = tstamp;
                    return Result.OK;
                }
                public Result onData(long written) {
                    if (written > this.size) {
                        throw new TestError("overread on '%s' (%d>%d)",
                                            this.fl, written, this.size);
                    }
                    return Result.OK;
                }
                public Result onDone(long total) {
                    String fpath = TestUtils.extractRelativePath(extractDir, this.fl);
                    if (total != this.size) {
                        throw new TestError("total mismatch '%s' (%d>%d)",
                                            fpath, total, this.size);
                    }
                    File parent;
                    if (setup.usingAbsolutePath()) {
                        parent = IOUtils.getRoot(rootDir);
                    }
                    else {
                        parent = 0 == fpath.length() ? rootDir : rootDir.getParentFile();
                    }
                    File obj = new File(parent, fpath);
                    if (!obj.exists()) {
                        throw new TestError("missing original object '%s'", obj.getAbsolutePath());
                    }
                    if (null != this.tstamp) {
                        // NOTE: root directory is in temporary folder which
                        //       might change, hence we should not check it...
                        boolean ird = obj.isDirectory() &&
                                      obj    .getAbsolutePath().length() <
                                      rootDir.getAbsolutePath().length();
                        if (!ird && obj.lastModified() != this.fl.lastModified()) {
                            throw new TestError("file '%s' time off by %,d",
                                fpath, obj.lastModified() - this.fl.lastModified());
                        }
                        if (this.tstamp != this.fl.lastModified()) {
                            throw new TestError("restored time of '%s' off by %,d",
                                fpath, this.tstamp - this.fl.lastModified());
                        }
                    }
                    if (this.fl.isDirectory() ^ obj.isDirectory()) {
                        throw new TestError("file '%s' dir/file mismatch", fpath);
                    }
                    if (!this.fl.isDirectory()) {
                        if (this.fl.length() != obj.length()) {
                            throw new TestError("size mismatch on '%s' by %,d",
                                    fpath, obj.length() - this.fl.length());
                        }
                        try {
                            if (!TestUtils.areFilesEqual(this.fl, obj)) {
                                throw new TestError("content mismatch on '%s'", fpath);
                            }
                        }
                        catch (IOException ioe) {
                            throw new TestError("I/O error while comparing (%s)",
                                                ioe.getMessage());
                        }
                    }
                    return Result.OK;
                }
            });
            FilePathWalker fpw = new FilePathWalker() {
                public boolean onObject(File obj) {
                    String fpath;
                    if (setup.usingAbsolutePath()) {
                        fpath = IOUtils.stripRoot(obj).toString();
                    }
                    else {
                        fpath = TestUtils.extractRelativePath(rootDir, obj);
                        if (0 < fpath.length()) {
                            fpath = rootDir.getName() + File.separatorChar + fpath;
                        }
                    }
                    File expected = new File(extractDir, fpath);
                    if (!expected.exists()) {
                        throw new TestError("'%s' not extracted!?", expected.getAbsolutePath());
                    }
                    if (expected.isDirectory() ^ obj.isDirectory()) {
                        throw new TestError("dir/file mismatch (%s)", fpath);
                    }
                    return true;
                }
            };
            fpw.walk(rootDir);
            if (!TestUtils.removeDir(extractDir, true)) {
                throw new TestError("removal of extraction tempdir '%s' failed",
                                    extractDir.getAbsolutePath());
            }
            tcr.close(false);
        };
    }

    ///////////////////////////////////////////////////////////////////////////

    public void fileTimeCheck(File obj, long tm) throws IOException {
        long ftm = obj.exists() ? obj.lastModified() : -1L;
        if (ftm != tm) {
            if (obj.equals(this.tmpDir)) {
                return;
            }
            throw new IOException(String.format(
                    "timestamp %d of file '%s' does not match %d (delta is %d)",
                    ftm,
                    obj.getAbsolutePath(),
                    tm,
                    ftm - tm));
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    public static byte[] decryptVolume(char[] passw, File inFile) throws Exception {
        Registry.setup(false);
        
        byte[] vdat = MiscUtils.readFile(inFile);

        Header hdr = new Header(new Password(passw, null), vdat, 0, false);

        if (hdr.dataAreaOffset != Header.SIZE) {
            throw new IOException("unexpected data area offset");
        }

        Volume vol = new Volume(BlockCipher.Mode.DECRYPT, hdr);

        long no = Header.BLOCK_COUNT;
        long end = no + (hdr.sizeofVolume / vol.blockSize());

        for (; no < end; no++) {
            int ofs = (int)no * vol.blockSize();

            vol.processBlock(no, vdat, ofs);
        }

        byte[] result = new byte[(int)hdr.sizeofVolume];
        System.arraycopy(vdat, Header.SIZE, result, 0, result.length);

        return result;
    }

    ///////////////////////////////////////////////////////////////////////////

    public static void decryptVolume(char[] passw,
            File inFile, File outFile) throws Exception {
        Registry.setup(false);
        
        byte[] buf = new byte[Header.SIZE];

        RandomAccessFile raf = new RandomAccessFile(inFile, "r");

        if (buf.length != IOUtils.readAll(raf, buf, 0, buf.length)) {
            throw new IOException("truncated 1st header");
        }

        Header hdr = new Header(new Password(passw.clone(), null), buf, 0, false);

        if (hdr.dataAreaOffset != Header.SIZE) {
            throw new IOException("unexpected data area offset");
        }

        Volume vol = new Volume(BlockCipher.Mode.DECRYPT, hdr);

        long no = Header.BLOCK_COUNT;
        long end = no + (hdr.sizeofVolume / vol.blockSize());

        FileOutputStream fos = new FileOutputStream(outFile);
        try {
            for (; no < end; no++) {
                if ((Header.BLOCK_SIZE != IOUtils.readAll(raf, buf, 0, Header.BLOCK_SIZE))) {
                    throw new IOException(String.format("block %d read incomplete", no));
                }

                vol.processBlock(no, buf, 0);
                fos.write(buf, 0, Header.BLOCK_SIZE);
            }
        }
        finally {
            fos.close();
        }

        if (buf.length != IOUtils.readAll(raf, buf, 0, buf.length)) {
            throw new IOException("truncated 2nd header");
        }

        Header hdr2 = new Header(new Password(passw, null), buf, 0, false);
        if (hdr.dataAreaSize != hdr2.dataAreaSize) {
            throw new IOException("header mismatch");
        }

        int rest = IOUtils.readAll(raf, buf, 0, buf.length);
        if (0 != rest) {
            throw new IOException(String.format(
                    "at least %d byte(s) of unexpected trailing data", rest));
        }

        raf.close();
    }

    ///////////////////////////////////////////////////////////////////////////

    public static Combo.Two<Verifier, Setup> makeVerSet(String[] args) throws Exception {
        String dir  = args[0];
        String fnms = 4 > args.length ? "nau" : args[3];

        final int  maxFiles = 2 > args.length ? 100     : Integer.parseInt(args[1]);
        final long maxBytes = 3 > args.length ? 1000000 : MiscUtils.strToUSz(args[2]);

        List<FileNameMaker> fnml = new ArrayList<>();

        for (char fnm : fnms.toLowerCase().toCharArray()) {
            switch (fnm) {
                case 'n' : fnml.add(new FileNameMaker.Numbered     ()); break;
                case 'a' : fnml.add(new FileNameMaker.RandomASCII  ()); break;
                case 'd' : fnml.add(new FileNameMaker.RandomDE     ()); break;
                case 'u' : fnml.add(new FileNameMaker.RandomUnicode()); break;
                default  : throw new Exception("unknown filename maker (n,a,u,d)");
            }
        }

        Verifier v = new Verifier(
                0xabcdef1111111111L,
                new File(dir),
                System.out,
                System.err,
                new FileNameMaker.Mixer(fnml.toArray(new FileNameMaker[0])),
                null);

        Setup s = new Setup() {
            public String[] basePath         () { return new String[0]; }
            public boolean  usingAbsolutePath() { return true; }
            public int      maxFiles         () { return maxFiles; }
            public int      maxPathLen       () { return 200; }
            public int      minSubDirsPerDir () { return 3; }
            public int      maxSubDirsPerDir () { return 10; }
            public int      minFilesPerDir   () { return 10; }
            public int      maxFilesPerDir   () { return 50; }
            public long     minFileSize      () { return 0; }
            public long     maxFileSize      () { return 10000; }
            public int      minFileNameLen   () { return 6; }
            public int      maxFileNameLen   () { return 80; }
            public long     maxBytes         () { return maxBytes; }
        };

        return new Combo.Two<>(v, s);
    }

    public static void main(String[] args) throws Exception {
        if (0 == args.length) {
            System.err.println("usage: verifier [dir] [maxfiles] [maxbytes] [naud]");
            return;
        }

        Combo.Two<Verifier, Setup> vs = makeVerSet(args);

        Creator.Result res = new Creator.Result();
        File root = vs.t.makeDirsAndFiles(vs.u, res);

        System.out.printf("--\nwrote %,d bytes to %,d files and %,d folders in %s\n",
                res.bytes,
                res.files,
                res.dirs,
                root.getAbsolutePath());
    }
}

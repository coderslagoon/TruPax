package coderslagoon.trupax.lib.prg;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;

import coderslagoon.baselib.io.BlockDevice;
import coderslagoon.baselib.io.BlockDeviceImpl;
import coderslagoon.baselib.io.DefaultFileSystemFilter;
import coderslagoon.baselib.io.FileNode;
import coderslagoon.baselib.io.FileRegistrar;
import coderslagoon.baselib.io.FileSystem;
import coderslagoon.baselib.io.IOUtils;
import coderslagoon.baselib.io.LocalFileSystem;
import coderslagoon.baselib.io.BlockDeviceImpl.FileBlockDevice;
import coderslagoon.baselib.io.FileRegistrar.Callback.Merge;
import coderslagoon.baselib.util.BaseLibException;
import coderslagoon.baselib.util.CmdLnParser;
import coderslagoon.baselib.util.Log;
import coderslagoon.baselib.util.MiscUtils;
import coderslagoon.baselib.util.Prp;
import coderslagoon.baselib.util.Routine;
import coderslagoon.baselib.util.VarInt;
import coderslagoon.baselib.util.VarRef;
import coderslagoon.baselib.util.Prp.Item;
import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.crypto.Rand;
import coderslagoon.tclib.crypto.Registry;
import coderslagoon.tclib.util.Key;
import coderslagoon.tclib.util.Password;
import coderslagoon.tclib.util.TCLibException;
import coderslagoon.trupax.lib.FATReader;
import coderslagoon.trupax.lib.NLS;
import coderslagoon.trupax.lib.Reader;
import coderslagoon.trupax.lib.UDFReader;
import coderslagoon.trupax.lib.UDFWriter;
import coderslagoon.trupax.lib.Wipe;
import coderslagoon.trupax.lib.Writer;
import coderslagoon.trupax.tc.TCBlockDevice;
import coderslagoon.trupax.tc.TCInvalidate;
import coderslagoon.trupax.tc.TCReader;

public class PrgImpl extends Prg {
    public final static int BLOCK_SIZE = 512;

    final static String LOG_CTX = "prg";

    String                  propsSaveFile;
    Properties              props;
    PrgProps                pprops = new PrgProps();
    String                  volumeFile;
    String                  extractDir;
    Long                    freeSpace = 0L;
    Long                    volumeSize;
    Boolean                 registerTopLevel;
    List<String>            objs = new ArrayList<>();
    FileNode[]              viewables;
    FileRegistrar           freg;
    Writer                  wrt;
    RegisterObjectsCallbacks rocb;

    ///////////////////////////////////////////////////////////////////////////

    private Result loadProps2(Setup setup) {
        if (setup.propertiesFile != null) {
            if (setup.propFileExists &&
                !Prp.loadFromFile(this.props, new File(setup.propertiesFile))) {
                return new Result(Result.Code.LOAD_PROPFILE_ERROR,
                        NLS.PRGIMPL_ERR_CANNOT_LOAD_PROPFILE.s(),
                        null);
            }
            if (null != setup.cb) {
                setup.cb.onProps();
            }
            if (setup.saveProperties) {
                this.propsSaveFile = setup.propertiesFile;
            }
        }

        Result result = processArgs(setup);
        if (result.isFailure()) {
            return result;
        }

        try {
            this.pprops.validate(this.props);
        }
        catch (Exception e) {
            return new Result(Result.Code.INVALID_PROPERTY,
                    NLS.PRGIMPL_INVALID_PROPERTY_1.fmt(e.getMessage()), null);
        }
        return result;
    }

    private Result loadProps(Setup setup) {
        Result result = loadProps2(setup);
        if (result.isFailure() && setup.resetOnLoadError) {
            if (null != setup.cb) {
                setup.cb.onLoadErrorReset(result);
            }
            this.props.clear();
            result = Result.ok();
        }
        return result;
    }

    private Result processArgs(Setup setup) {
        String[] args = setup.args;
        if (null == args) {
            args = new String[0];
        }
        else {
            for (int i = 0; i < args.length; i++) {
                args[0] = args[0].trim();
            }
        }

        CmdLnParser ap;
        try {
            ap = this.pprops.parseArgs(args);
        }
        catch (PrgException pe) {
            return new Result(Result.Code.INVALID_CMDLN_ARG,
                              pe.getLocalizedMessage(), null);
        }

        this.props.putAll(ap.options());

        final int c = ap.params().size();
        int i = -1;
        if (setup.fromCommandLine) {
            boolean nep = false;
            switch(setup.initOp) {
                case WIPE      : if (1 >  c) nep = true; else i = 0; break;
                case EXTRACT   : if (2 >  c) nep = true; else i = 1; break;
                case INVALIDATE: if (1 != c) nep = true; else i = 1; break;
                case DEFAULT   :
                default        : if (2 >  c) nep = true; else i = 1; break;
            }
            if (nep) {
                return new Result(
                    Result.Code.MISSING_CMDLN_ARG,
                    NLS.PRGIMPL_NOT_ENOUGH_PARAMS.s(),
                    null);
            }
            if (1 == i) {
                this.volumeFile = ap.params().get(0);
            }
        }
        else {
            i = 0;
        }

        if (setup.initOp == Setup.InitOp.EXTRACT) {
            this.extractDir = i < c ? ap.params().get(i) : ".";
        }
        else if (setup.initOp != Setup.InitOp.INVALIDATE) {
            for (; i < c; i++) {
                this.objs.add(ap.params().get(i));
            }
        }

        return 0 == c ? Result.ok() : new Result(
                Result.Code.GOT_OBJECTS, Integer.valueOf(c).toString(), null);
    }

    ///////////////////////////////////////////////////////////////////////////

    public static Result init() {
        try {
            NLS.Reg.instance().load(null);
        }
        catch (BaseLibException ble) {
            return new Result(Result.Code.INTERNAL_ERROR,
                    "NLS load error", ble.getMessage());
        }
        try {
            Registry.setup(true);
            return Result._ok;
        }
        catch (TCLibException tcle) {
            return new Result(Result.Code.ALGORITHM_TEST_ERROR,
                    NLS.PRGIMPL_ALGORITHM_TEST_ERROR.s(),
                    tcle.getLocalizedMessage());
        }
    }

    public static Result cleanup() {
        return Result._ok;
    }

    ///////////////////////////////////////////////////////////////////////////

    public PrgImpl() {
    }

    ///////////////////////////////////////////////////////////////////////////

    public Result ctor(Properties props, Setup setup) {
        this.props = props;
        if (null != setup) {
            Result res = loadProps(setup);
            if (res.isFailure()) {
                return res;
            }
        }
        return registerClear();
    }

    public Result dtor() {
        if (null != this.propsSaveFile) {
            if (!Prp.saveToFile(this.props, new File(this.propsSaveFile), true,
                                  NLS.PRGIMPL_PROPS_COMMENT.s())) {
                return new Result(Result.Code.LOAD_PROPFILE_ERROR,
                    NLS.PRGIMPL_ERR_CANNOT_SAVE_PROPFILE.s(), null);
            }
        }
        return Result.ok();
    }

    ///////////////////////////////////////////////////////////////////////////

    public String getProperty(String name) {
        Object result = this.props.get(name);
        return null == result ? null : result.toString();
    }

    public PropertyInfo getPropertyInfo(String name) {
        try {
            return this.pprops.getInfo(name);
        }
        catch (Exception e) {
            return null;
        }
    }

    public Result setProperty(final NamedString prop) {
        try {
            Result result = verifyProperty(prop);
            if (result.isSuccess()) {
                PrgImpl.this.props.put(prop.name, prop.value);
            }
            return result;
        }
        catch (Exception e) {
            return Result.internalError(e);
        }
    }

    public Result verifyProperty(NamedString prop) {
        try {
            Item<?> item = this.pprops.get(prop.name);
            if (null == item) {
                return new Result(Result.Code.UNKNOWN_PROPERTY,
                        NLS.PRGIMPL_UNKNOWN_PROPERTY_1.fmt(prop.name), null);
            }
            if (!item.validate(prop.value)) {
                return new Result(Result.Code.INVALID_PROPERTY,
                        NLS.PRGIMPL_INVALID_PROPERTY_VALUE_2.fmt(
                        prop.value, prop.name), null);
            }
            return Result.ok();
        }
        catch (Exception e) {
            return Result.internalError(e);
        }
    }

    public Result addObject(String obj) {
        this.objs.add(obj);
        return Result.ok();
    }

    public Result setVolumeFile(String file) {
        this.volumeFile = file;
        return Result.ok();
    }

    public Result setFreeSpace(long sz) {
        this.freeSpace = sz;
        return Result.ok();
    }

    ///////////////////////////////////////////////////////////////////////////

    public Result clearObjects() {
        this.objs.clear();
        return Result.ok();
    }

    public Result registerClear() {
        this.freg = new FileRegistrar.InMemory(new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                checkConfig();
                return this.allowMerge && this.caseMerge ?
                    o1.compareTo          (o2) :
                    o1.compareToIgnoreCase(o2);
            }
            void checkConfig() {
                if (null == this.allowMerge) {
                    this.allowMerge = new PrgProps.AllowMerge().get(PrgImpl.this.props);
                    this.caseMerge  = new PrgProps.CaseMerge ().get(PrgImpl.this.props);
                    PrgImpl.this.rocb.onConfigLocked();
                }
            }
            Boolean allowMerge;
            Boolean caseMerge;
        });
        dirty();
        return Result.ok();
    }

    public Result registerObjects(final RegisterObjectsCallbacks cb) {
        dirty();
        this.rocb = cb;

        final boolean storeFullPath = new PrgProps.StoreFullPath  ().get(this.props);
        final boolean skipEmptyDirs = new PrgProps.SkipEmptyDirs  ().get(this.props);
        final boolean recursive     = new PrgProps.RecursiveSearch().get(this.props);
        final boolean allowMerge    = new PrgProps.AllowMerge     ().get(this.props);
        final boolean trimPath      = new PrgProps.TrimPath       ().get(this.props);

        final LocalFileSystem lfs = new LocalFileSystem(storeFullPath);

        final List<FileNode> singleFile = new ArrayList<>();

        final Routine.Arg2<FileRegistrar.Callback.Merge, FileNode, FileNode> onMerge = (arg1, arg2) -> {
            boolean dir0 = arg1.hasAttributes(FileNode.ATTR_DIRECTORY);
            boolean dir1 = arg2.hasAttributes(FileNode.ATTR_DIRECTORY);
            if (dir0 && dir1) {
                return Merge.IGNORE;
            }
            if (dir0 ^ dir1) {
                return Merge.ABORT;
            }
            return allowMerge ? Merge.REPLACE : Merge.ABORT;
        };

        for (String obj : this.objs) {
            FileNode fn;
            final VarRef<FileSystem.Filter> fsf = new VarRef<>();

            String[] em = IOUtils.extractMask(obj);
            if (null != em) {
                fsf.v = new DefaultFileSystemFilter(em[1]);
                obj = em[0];
                if (null == obj) {
                    obj = ".";
                }
            }

            try {
                fn = lfs.nodeFromString(obj);

                if (!lfs.exists(fn)) {
                    return new Result(
                        Result.Code.ERROR_OBJECT_REGISTER,
                        NLS.PRGIMPL_NO_SUCH_OBJ_REG_1.fmt(obj),
                        null);
                }
            }
            catch (IOException ioe) {
                return new Result(
                        Result.Code.ERROR_OBJECT_REGISTER,
                        NLS.PRGIMPL_ERR_OBJ_REG_1.fmt(obj),
                        ioe.getLocalizedMessage());
            }

            FileNode fnl = fn;
            if (!trimPath) {
                while (null != fnl.parent()) {
                    fnl = fnl.parent();
                }
            }

            try {
                if (fn.hasAttributes(FileNode.ATTR_DIRECTORY)) {
                    final VarRef<String> details = new VarRef<>();
                    final int res = FileRegistrar.bulk(
                        this.freg,
                        fn,
                        storeFullPath ? null : fnl,
                        null,
                        new FileRegistrar.BulkCallbacks() {
                            public boolean onProgress(FileNode current) {
                                return cb.onDirectory(current.path(false)).isSuccess();
                            }
                            public Merge onMerge(FileNode[] nd0, FileNode nd1) {
                                Merge merge = onMerge.call(nd0[0], nd1);
                                if (Merge.ABORT == merge) {
                                    details.v = nd1.path(true);
                                }
                                return onMerge.call(nd0[0], nd1);
                            }
                            public boolean matches(FileNode file) {
                                if (null != fsf.v &&
                                    !file.hasAttributes(FileNode.ATTR_DIRECTORY)) {
                                    return fsf.v.matches(file);
                                }
                                return true;
                            }
                        },
                        recursive,
                        !skipEmptyDirs);

                    switch(res) {
                        case FileRegistrar.BULKERR_INTERNAL : return Result.internalError(null);
                        case FileRegistrar.BULKERR_ABORTED  : return Result.aborted();
                        case FileRegistrar.BULKERR_COLLISION: return new Result(
                                Result.Code.FILE_COLLISION,
                                NLS.PRGIMPL_FILE_COLLISION.s(), details.v);
                    }
                }
                else {
                    singleFile.clear();
                    singleFile.add(fn);

                    if (!this.freg.add(
                            singleFile,
                            storeFullPath ? null : fnl,
                            null,
                            (nd0, nd1) -> onMerge.call(nd0[0], nd1))) {
                        return new Result(Result.Code.FILE_COLLISION,
                                          NLS.PRGIMPL_FILE_COLLISION.s(),
                                          fn.path(true));
                    }
                }
            }
            catch (IOException ioe) {
                return new Result(
                    Result.Code.ERROR_OBJECT_REGISTER,
                    NLS.PRGIMPL_REG_SEARCH_FAILED_1.fmt(fn.path(true)),
                    ioe.getLocalizedMessage());
            }
        }

        //FileRegistrar.dump(this.freg.root(), 0, System.out);

        return Result.ok();
    }

    ///////////////////////////////////////////////////////////////////////////

    void dirty() {
        this.viewables = null;
    }

    void loadViewables() {
        if (null == this.viewables) {
            final VarInt count = new VarInt();
            FileRegistrar.walk(this.freg.root(), fn -> {
                        count.v++;
                        return true;
                    },
                    true,
                    true);
            this.viewables = new FileNode[count.v];
            final VarInt i = new VarInt();
            FileRegistrar.walk(this.freg.root(), fn -> {
                        PrgImpl.this.viewables[i.v++] = fn[0];
                        return true;
                    },
                    true,
                    true);
        }
    }

    public int registerViewCount() {
        loadViewables();
        return this.viewables.length;
    }

    public RegObj[] registerView(final int from, final int to) {
        loadViewables();
        final int c = to - from;
        final RegObj[] result = new RegObj[c];
        for (int i = 0; i < c; i++) {
            final FileNode fn = this.viewables[from + i];
            result[i] = new RegObj(
                    FileRegistrar.nodePath(fn),
                    fn.hasAttributes(FileNode.ATTR_DIRECTORY) ? -1L : fn.size(),
                    fn.timestamp(),
                    fn.path(true));
        }
        return result;
    }

    public void registerViewSort(final RegObj.Sort sort, final boolean ascending) {
        loadViewables();
        Arrays.sort(this.viewables, (fn1, fn2) -> {
            int r = 0;
            switch (sort) {
                case NAME:
                {   // FIXME: optimize using weakref
                    r = fn1.path(true).compareTo(fn2.path(true));
                    break;
                }
                case LENGTH: {
                    long l1 = fn1.hasAttributes(FileNode.ATTR_DIRECTORY) ? -1L : fn1.size();
                    long l2 = fn2.hasAttributes(FileNode.ATTR_DIRECTORY) ? -1L : fn2.size();
                    long d = l1 - l2;
                    r = 0 == d ? 0 : (0 < d ? 1 : -1);
                    break;
                }
                case TIMESTAMP: {
                    long d = fn1.timestamp() - fn2.timestamp();
                    r = 0 == d ? 0 : (0 < d ? 1 : -1);
                    break;
                }
            }
            return r * (ascending ? 1 : -1);
        });
    }

    ///////////////////////////////////////////////////////////////////////////

    public RegSum registerSummary() {
        FileRegistrar.Walker.Counting fwc = new FileRegistrar.Walker.Counting();

        FileRegistrar.walk(this.freg.root(), fwc, true, false);

        RegSum result = new RegSum();

        result.numberOfDirectories = fwc.directories;
        result.numberOfFiles       = fwc.files;
        result.bytesTotal          = fwc.bytesTotal;

        return result;
    }

    ///////////////////////////////////////////////////////////////////////////

    protected static boolean __TEST_make_npe;
    protected static boolean __TEST_write_error;

    public Result make(char[] password, final MakeCallback cb) {
        if (null == this.volumeFile) {
            return new Result(Result.Code.MAKE_REJECT,
                    NLS.PRGIMPL_MAKE_REJECT_NOVOL.s(), null);
        }
        File vol = null;
        try {
            BlockDevice outdev;
            try {
                vol = new File(this.volumeFile);

                if (vol.exists() && !new PrgProps.Overwrite().get(this.props)) {
                    vol = null;  // avoids volume being deleted during the cleanup below
                    return new Result(Result.Code.VOLUME_EXISTS,
                            NLS.PRGIMPL_VOL_EXISTS.s(), null);
                }

                @SuppressWarnings("resource")
                final OutputStream os = new BufferedOutputStream(new FileOutputStream(vol));

                OutputStream os2 = new OutputStream() {
                    public void close()                             throws IOException { os.close(); }
                    public void flush()                             throws IOException { os.flush(); }
                    public void write(byte[] buf, int ofs, int len) throws IOException { t(); os.write(buf, ofs, len); }
                    public void write(byte[] buf)                   throws IOException { t(); os.write(buf); }
                    public void write(int b)                        throws IOException { t(); os.write(b); }
                    void t() throws IOException { if (__TEST_write_error) throw new IOException("FAKE_WRITE_"); }
                };

                outdev = new BlockDeviceImpl.OutputStreamBlockDevice(
                        os2,
                        this.volumeSize,
                        BLOCK_SIZE,
                        true);
            }
            catch (IOException ioe) {
                return new Result(Result.Code.CREATE_VOLUME_ERROR,
                        NLS.PRGIMPL_CREATE_VOLUME_ERROR.s(),
                        ioe.getLocalizedMessage());
            }

            BlockDeviceImpl.HookBlockDevice houtdev = new
            BlockDeviceImpl.HookBlockDevice(outdev) {
                protected boolean onRead(long num) { throw new Error(); }
                protected boolean onWrite(long num) {
                    return cb.onVolumeWrite(num * BLOCK_SIZE).isSuccess();
                }
            };

            Result result = cb.onKeyGen(); 
            if (Result.Code.ABORTED == result.code) {
                return result;
            }
            
            TCBlockDevice tcbdev;
            try {
                final Key key = new Password(password, null);

                String  hashFunction = new PrgProps.HashFunction().get(this.props);
                String  blockCipher  = new PrgProps.BlockCipher ().get(this.props);
                boolean forVeraCrypt = new PrgProps.ForVeraCrypt().get(this.props);

                tcbdev = new TCBlockDevice(
                        houtdev,
                        key,
                        hashFunction,
                        blockCipher,
                        forVeraCrypt,
                        Rand.wrap(Rand.secure()));

                outdev = null;
            }
            catch (BlockDevice.AbortException ae) {
                return Result.aborted();
            }
            catch (IOException ioe) {
                return new Result(Result.Code.CREATE_VOLUME_ERROR,
                        NLS.PRGIMPL_INIT_TC_BLOCKDEV_ERROR_1.fmt(
                                ioe.getLocalizedMessage()),
                        MiscUtils.dumpError(ioe));
            }
            catch (TCLibException tle) {
                return new Result(Result.Code.INTERNAL_ERROR,
                        NLS.PRGIMPL_INTERNAL_ERROR_1.fmt(
                                tle.getLocalizedMessage()),
                        MiscUtils.dumpError(tle));
            }
            finally {
                if (null != outdev) {
                    try { outdev.close(true); }
                    catch (IOException ignored) { }
                }
            }

            try {
                this.wrt.make(tcbdev, (dir, node) -> {
                    if (null == dir && null == node) {
                        cb.onFreeSpace();
                        return;
                    }
                    cb.onFile(node.path(false), node.size());
                    if (__TEST_make_npe) {
                        throw new NullPointerException("MAKE_NPE");
                    }
                });

                tcbdev.close(false);
                tcbdev = null;

                vol = null;
                return Result.ok();
            }
            catch (BlockDevice.AbortException ae) {
                return Result.aborted();
            }
            catch (IOException ioe) {
                return new Result(Result.Code.MAKE_ERROR,
                        NLS.PRGIMPL_MAKE_ERROR_1.fmt(ioe.getLocalizedMessage()),
                        MiscUtils.dumpError(ioe));
            }
            finally {
                if (null != tcbdev) {
                    try {
                        tcbdev.close(null != vol);
                    }
                    catch (IOException ignored) {
                    }
                }
            }
        }
        finally {
            if (null != vol && !new PrgProps.KeepBrokenVolume().get(this.props)) {
                if (!vol.delete() && vol.exists()) {
                    Log.print(Log.Level.WARN, LOG_CTX, "cannot remove broken volume");
                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    public Result resolve() {
        this.wrt = new UDFWriter(this.freg, this.props);

        try {
            this.volumeSize = this.wrt.resolve(new Writer.Layout() {
                public long freeBlocks() {
                    return PrgImpl.this.freeSpace / blockSize() +
                     (0 == PrgImpl.this.freeSpace % blockSize() ? 0 : 1);
                }
                public int blockSize() {
                    return BLOCK_SIZE;
                }
                public String label() {
                    return new PrgProps.Label().get(PrgImpl.this.props);
                }
                public boolean writeProtect() {
                    return new PrgProps.WriteProtect().get(PrgImpl.this.props);
                }
            }) + Header.BLOCK_COUNT * 2;
        }
        catch (IOException ioe) {
            return new Result(Result.Code.RESOLVE_ERROR,
                    NLS.PRGIMPL_RESOLVE_ERROR.s(),
                    ioe.getLocalizedMessage());
        }

        return Result.ok();
    }

    ///////////////////////////////////////////////////////////////////////////

    public long volumeBytes() {
        return null == this.volumeSize ? -1L : (BLOCK_SIZE * this.volumeSize);
    }

    ///////////////////////////////////////////////////////////////////////////

    public Result wipe(final WipeCallback wcb) {
        Wipe w = new Wipe(this.freg, new Wipe.Cycles.Zeros(), true);
        return w.perform(new Wipe.Progress() {
            public boolean onNode(FileNode fn) {
                if (!fn.hasAttributes(FileNode.ATTR_DIRECTORY)) {
                    wcb.onFile(fn.path(true), fn.size());
                }
                return true;
            }
            public boolean onProcessed(double percent) {
                return wcb.onProgress(percent).isSuccess();
            }
            public boolean onSkipped(FileNode fn, Reason reason) {
                return wcb.onConcern(Concern.SKIP,
                        wipeReasonToConcernMessage(reason)).isSuccess();
            }
            public boolean onError(FileNode fn, Reason reason) {
                return wcb.onConcern(Concern.ERROR,
                        wipeReasonToConcernMessage(reason)).isSuccess();
            }
            public boolean onWarning(FileNode fn, Reason reason) {
                return wcb.onConcern(Concern.WARNING,
                        wipeReasonToConcernMessage(reason)).isSuccess();
            }
        }) ? Result.ok() : Result.aborted();
    }

    static String wipeReasonToConcernMessage(Wipe.Progress.Reason wpr) {
        switch(wpr) {
            case VANISHED      : return NLS.PRGIMPL_WIPE_REASON_VANISHED  .s();
            case CANNOT_OPEN   : return NLS.PRGIMPL_WIPE_REASON_CANNOTOPEN.s();
            case IO_ERROR      : return NLS.PRGIMPL_WIPE_REASON_IOERROR   .s();
            case RENAME1_FAILED: return NLS.PRGIMPL_WIPE_REASON_RENFAILED .s();
            case RENAME2_FAILED: return NLS.PRGIMPL_WIPE_REASON_REN2FAILED.s();
            case DELETE_FAILED : return NLS.PRGIMPL_WIPE_REASON_DELFAILED .s();
            default: {
                return NLS.PRGIMPL_WIPE_REASON_UNKNOWN_1.fmt(wpr.toString());
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    public Result extract(char[] password, String dir, final ExtractCallback cb) {
        RandomAccessFile raf = null;
        BlockDevice bdev = null;
        TCReader tcr = null;
        try {
            raf = new RandomAccessFile(this.volumeFile, "r");
            bdev = new BlockDeviceImpl.FileBlockDevice(raf, BLOCK_SIZE, -1L, true, false);
            final Key key = new Password(password, null);
            tcr = new TCReader(bdev, key, false, true);
        }
        catch (IOException ioe) {
            return new Result(Result.Code.CANNOT_OPEN,
                NLS.PRGIMPL_CANNOT_OPEN_VOLUME_1.fmt(this.volumeFile),
                ioe.getLocalizedMessage());
        }
        catch (TCLibException tle) {
            return new Result(Result.Code.CANNOT_DECRYPT,
                NLS.PRGIMPL_CANNOT_UNLOCK_VOLUME.s(),
                tle.getLocalizedMessage());
        }
        finally {
            if (null == tcr && null != raf) {
                try { raf.close(); } catch (IOException ignored) { }
            }
        }

        Reader rmul = new Reader.Multiple(new Reader[] {
            new UDFReader(tcr, this.props),
            new FATReader(tcr, this.props) });

        try {
            if (null == dir) {
                dir = this.extractDir;
            }
            rmul.extract(new File(dir), new Reader.Progress2() {
                public Result onMounting(int numOfObjects) {
                    return cb.onOpening(numOfObjects).code ==
                        Prg.Result.Code.ABORTED ? Result.ABORT : Result.OK;
                }
                public Result onMount(int numOfFiles, int numOfDirs) {
                    return cb.onOpen(numOfFiles, numOfDirs).code ==
                        Prg.Result.Code.ABORTED ? Result.ABORT : Result.OK;
                }
                public Result onDirectory(File obj, long size, Long tstamp) {
                    this.report = false;
                    return Result.OK;
                }
                public Result onFile(File obj, long size, Long tstamp) {
                    this.report = true;
                    if (!this.overwrite && obj.exists()) {
                        switch (cb.onConcern(
                            Concern.EXISTS, NLS.PRGIMPL_EXTRACT_FILE_EXISTS_3.fmt(
                                obj.getAbsolutePath(),
                                obj.length(),
                                size)).code) {
                            case IGNORE : return Result.SKIP;
                            case ABORTED: return Result.ABORT;
                            default     : break;
                        }
                    }
                    cb.onFile(obj.getAbsolutePath(), size);
                    return Result.OK;
                }
                public Result onData(long written) {
                    if (this.report &&
                        Prg.Result.Code.ABORTED == cb.onFileWrite(written).code) {
                        return Result.ABORT;
                    }
                    return Result.OK;
                }
                public Result onDone(long total) {
                    return onData(total);
                }
                boolean report;
                boolean overwrite = new PrgProps.Overwrite().get(PrgImpl.this.props);
            });
            return Result.ok();
        }
        catch (Reader.Exception re) {
            switch(re.code) {
                case ABORTED: return Result.aborted();
                case ERR_DEV: return new Result(
                    Result.Code.EXTRACT_ERROR,
                    NLS.PRGIMPL_EXTERR_DEV.s(),
                    re.details);
                default: return new Result(
                    Result.Code.EXTRACT_ERROR,
                    NLS.PRGIMPL_EXTERR_OBJ_2.fmt(
                          null == re.obj ? "" : re.obj.getAbsolutePath(),
                          re.code.toString()),
                    re.details);
            }
        }
        catch (IOException ioe) {
            return new Result(Result.Code.EXTRACT_ERROR,
                    NLS.PRGIMPL_EXTERR_FAIL.s(),
                    ioe.getLocalizedMessage());
        }
        finally {
            try { raf.close(); } catch (IOException ignored) { }
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    public Result invalidate(final ProgressCallback cb) {
        try {
            FileBlockDevice fbd = null;
            boolean err = true;
            final File fl = new File(this.volumeFile);
            try {
                if (!fl.exists()) {
                    throw new TCLibException(String.format(
                        NLS.PRGIMPL_FILE_NOT_FOUND_1.s(), fl.getAbsolutePath()));
                }

                RandomAccessFile raf = new RandomAccessFile(fl, "rws");
                fbd = new FileBlockDevice(raf, BLOCK_SIZE, -1, false, false);

                boolean aborted = !TCInvalidate.destroy(fbd, TCInvalidate.HeaderChange.zeros(),
                    new TCInvalidate.Progress() {
                        double max;
                        long pos, step;
                        double percent() {
                            return (this.pos * 100L) / this.max;
                        }
                        public boolean onStart(long blocks, int blockSize) {
                            this.step = blockSize;
                            this.pos = 0L;
                            this.max = blockSize * blocks;
                            return cb.onProgress(percent()).isSuccess();
                        }
                        public boolean onBlock() {
                            this.pos += this.step;
                            return cb.onProgress(percent()).isSuccess();
                        }
                    });
                err = false;
                if (aborted) {
                    return Result.aborted();
                }
            }
            catch (TCLibException tle) {
                return new Result(Result.Code.INVALIDATE_ERROR,
                    NLS.PRGIMPL_INVALIDATE_ERR_1.fmt(tle.getMessage()), null);
            }
            catch (IOException ioe) {
                return new Result(Result.Code.INVALIDATE_ERROR,
                    NLS.PRGIMPL_INVALIDATE_ERR_1.fmt(ioe.getMessage()), null);
            }
            finally {
                if (null != fbd) {
                    try { fbd.close(err); } catch (IOException ignored) { }
                }
            }
            if (new PrgProps.DeleteAfter().get()) {
                if (!fl.delete()) {
                    return new Result(Result.Code.INVALIDATE_ERROR,
                                      NLS.PRGIMPL_INVALIDATE_ERRDEL.s(), null);
                }
            }
            return Result.ok();
        }
        finally {
            this.volumeFile = null;
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    @Override
    public void addRandomSeed(long seed) {
        Rand.secure().setSeed(seed);
    }
}

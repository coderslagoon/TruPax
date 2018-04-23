package coderslagoon.trupax.lib.prg;

import java.io.Serializable;
import java.util.Properties;

import coderslagoon.baselib.util.MiscUtils;
import coderslagoon.trupax.lib.NLS;

/**
 * TruPax program interface. The whole interaction with a TruPax instance
 * happens through this. The API itself was designed in a flat, structured
 * style, so it can be accessed through potentially different bindings
 * without too much translation required. Implementations are supposed to be
 * thread-safe, meaning one instance per thread, but multiple instances can
 * be present at the same time in the same process.
 * @author CODERSLAGOON
 */
public abstract class Prg {
    final static int VERSION = 9;
    final static String RELEASE = "C";

    /**
     * Returns the version number. Mainly for display purposes. Comparisons
     * can be made for "not equal".
     * @return The version number as an arbitrary string.
     */
    public static String version() {
        final boolean sb = null != RELEASE;
        return String.format("%d%s%s",
                             VERSION,
                             sb ? " " : "",
                             sb ? RELEASE : "");
    }

    ///////////////////////////////////////////////////////////////////////////

    /** Maximum length (in characters) a volume label can have. */
    public final static int MAX_LABEL_LEN = 15;

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Base class for all structures. The notion is to define them as a C-like
     * as possible, allowing serialization and to have them as mere data
     * storage with direct field and simple method access only. The meaning of
     * any constructor is simple population of the fields, nothing else.
     */
    protected static abstract class Struct implements Serializable {
        private static final long serialVersionUID = 6549894299720993360L;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Base structure for anything which is named.
     */
    protected abstract static class Named extends Struct {
        private static final long serialVersionUID = -7039237542537298672L;
        protected Named(String name) { this.name = name; }
        public final String name;
    }
    /**
     * Simple name/value pair.
     */
    public static class NamedString extends Named {
        private static final long serialVersionUID = 750480559151430566L;
        public NamedString(String name, String value) {
            super(name);
            this.value = value;
        }
        public final String value;
    }

    /**
     * Registered object, which can be either a file or directory. The name
     * contains the path-to-be in the volume.
     */
    public static class RegObj extends Named {
        private static final long serialVersionUID = -6898521673964266954L;
        public RegObj(String name, long length, long timestamp, String path) {
            super(name);
            this.length    = length;
            this.timestamp = timestamp;
            this.path      = path;
        }
        /** Length of a file. Undefined for directories. */
        public final long length;
        /** The time-stamp of the object. Regular Java format. */
        public final long timestamp;
        /** The file-system specific (&quot;real&quot;) path. */
        public final String path;
        /**
         * To determine if the object is a directory.
         * @return False if the object is a file.
         */
        public boolean isDir() {
            return -1 == this.length;
        }
        /** Sort order definitions, used when lists of objects are returned. */
        public enum Sort {
            NAME,
            LENGTH,
            TIMESTAMP
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Return value of any API call. Used as an alternative to exceptions, to
     * have just one point of return for results.
     */
    public static class Result extends Struct {
        private static final long serialVersionUID = 7811993492073267939L;

        /**
         * Error code of a result.
         */
        public enum Code {
            /** The operation was successful. */
            OK(0),
            /** Some internal problem occurred. This should not happen and
             * very likely indicates a bug. Please report. */
            INTERNAL_ERROR(1),
            /** Generic error code for a non-operational system or setup. */
            PRG_ERROR(2),
            /** The some self-test routine for a cryptographic operation failed.
             * This usually means that the executable got corrupted or the
             * source code got modified. */
            ALGORITHM_TEST_ERROR(3),
            /** The operation was aborted (by a callback). */
            ABORTED(4),
            /** An invalid command line argument got detected. */
            INVALID_CMDLN_ARG(5),
            /** One or more command line arguments are missing. */
            MISSING_CMDLN_ARG(6),
            /** The registration of a file or directory failed. Example reasons
             * are access problems or objects which vanished. */
            ERROR_OBJECT_REGISTER(7),
            /** The property file could not be loaded. */
            LOAD_PROPFILE_ERROR(8),
            /** The property file could not be saved. NOT USED! */
            SAVE_PROPFILE_ERROR(9),
            /** Some problem occurred during the computation of the volume
             * layout and size. */
            RESOLVE_ERROR(10),
            /** The creation of the volume file file. Reasons could be that
             * the target is write-protected or missing access rights. */
            CREATE_VOLUME_ERROR(11),
            /** The setup hasn't been completed yet (missing password etc),
             * so the making of the volume cannot commence. */
            MAKE_REJECT(12),
            /** Something went wrong during the creation of the volume. */
            MAKE_ERROR(13),
            /** Newly added material conflicts with already registered one,
             * there is some overlap in files and/or directories. */
            FILE_COLLISION(14),
            /** The volume file exists already and the instance is not
             * configured to overwrite it. */
            VOLUME_EXISTS(15),
            /** A property of an unknown name was found. */
            UNKNOWN_PROPERTY(16),
            /** The value of a property is invalid, e.g. when a number was
             * excepted something different was set. */
            INVALID_PROPERTY(17),
            /** Objects got passed in the command line and are now registered.
             * Returned by the constructor method of an implementation. */
            GOT_OBJECTS(18),
            /** Generic signal to tell the caller to ignore an issue. Can be
             * returned by a callback to indicate that despite a problem the
             * operation should continue. */
            IGNORE(19),
            /** The volume couldn't the opened. This could be an access or some
             * other I/O related issue. */
            CANNOT_OPEN(20),
            /** Volume opening failed because of header damage or a password
             * mismatch. */
            CANNOT_DECRYPT(21),
            /** Volume extraction failed. There are many reasons like I/O
             * problems or UDF file system corruption. */
            EXTRACT_ERROR(22),
            /** Volume invalidation failed. Usually an I/O error. */
            INVALIDATE_ERROR(23);

            private Code(int value) {
                this.value = value;
            }
            /**
             * Numerical value of an error code. Explicitly declared because
             * these values also are supposed to be returned as process exit
             * codes.
             */
            public final int value;
        }

        /** The error code of the result. */
        public final Code code;
        /** Status message of the result. Single line of text. Localized too,
         * but might be null for non-errors. */
        public final String msg;
        /** Details about the problem. Not localized and potential cryptic,
         * thus something more suitable for logs and error reporting, and less
         * for the end user to to see. Might be null. */
        public final String details;

        public Result(Code code, String msg, String details) {
            this.code    = code;
            this.msg     = msg;
            this.details = details;
        }

        /**
         * Helper to determine if a result indicates success or not.
         * @return True for success.
         */
        public final boolean isSuccess() {
            return this.code == Code.OK ||
                   this.code == Code.GOT_OBJECTS;
        }

        /**
         * Helper to determine if a result indicates failure.
         * @return True for (true) failure.
         */
        public final boolean isFailure() {
            return !isSuccess();
        }

        /**
         * Returns a result with code OK with null for message and details.
         * @return Static instance.
         */
        public final static Result ok() {
            return _ok;
        }
        final static Result _ok = new Result(Code.OK, null, null);

        /**
         * Returns a new result with code ABORTED, localized message and null
         * for details.
         * @return New instance.
         */
        public final static Result aborted() {
            return new Result(Code.ABORTED, NLS.PRG_OPERATION_ABORTED.s(), null);
        }

        /**
         * Creates a result of INTERNAL_ERROR out of an exception. The message
         * is the one of the exception, the details contain the stack dump as
         * text of multiple lines.
         * @param err The exception to transform.
         * @return The new result instance.
         */
        public final static Result internalError(Throwable err) {
            return new Result(Result.Code.INTERNAL_ERROR,
                    NLS.PRGIMPL_INTERNAL_ERROR_1.fmt(
                        null == err ? null : err.getLocalizedMessage()),
                        null == err ? null : MiscUtils.dumpError(err));
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Official names for the supported properties. The default value of all
     * booleans is "false". Notice that there is no need to set any properties
     * if the default settings are acceptable.
     */
    public static class Prop {
        final static String PFX = "trupax.prg.";

        /**
         * Whether to search directories recursively (and by that registering
         * all of their content) or not, meaning just the files they contain.
         * Boolean.
         */
        public final static String RECURSIVE_SEARCH = PFX + "recursivesearch";
        /**
         * Whether to store the full (absolute path) of objects (true) or if
         * only the relative path, from the original search point on, should be
         * registered. Boolean.
         */
        public final static String STORE_FULL_PATH = PFX + "storefullpath";
        /**
         * Whether to register the full path or just the relative portion from
         * a given original path. This allows e.g. to handle drag-and-drop
         * file paths to be made relative although technically an absolute
         * path was added. Boolean.
         */
        public final static String TRIM_PATH = PFX + "trimpath";
        /**
         * Whether empty directories should be registered or not. Boolean.
         */
        public final static String SKIP_EMPTY_DIRS = PFX + "skipemptydirs";
        /**
         * Whether collisions of files and directory names should be allowed.
         * If latter the material of the latest registration will replace the
         * one of the previous ones in the tree. This mixing might be less
         * favorable if the user doesn't have a clear picture of what the mix
         * actually looks like. Boolean.
         */
        public final static String ALLOW_MERGE = PFX + "allowmerge";
        /**
         * Collisions are detected only if the names of files and folders do
         * match exactly (true). Otherwise (false) collisions can be caused in
         * a not case-sensitive way (e.g. "test" and "TeSt" are equal).
         */
        public final static String CASE_MERGE = PFX + "casemerge";
        /**
         * Whether files are allowed to be overwritten or not. This applies to
         * both the creation of volumes as well as for extraction. Boolean.
         */
        public final static String OVERWRITE = PFX + "overwrite";
        /**
         * Whether to make the (UDF) volume write-protected (true) or not.
         * Actual honoring of the file system flag depends on the individual
         * OS mounting it. Boolean.
         */
        public final static String WRITEPROTECT = PFX + "writeprotect";
        /**
         * The name of the block cipher to use. Default is "AES256". String.
         */
        public final static String BLOCK_CIPHER = PFX + "blockcipher";
        /**
         * The name of the hash function to use. Default is "SHA-512". String.
         */
        public final static String HASH_FUNCTION = PFX + "hashfunction";
        /**
         * Whether to keep a volume after creation has failed. This is something
         * you might only really want to use for debugging purposes, since
         * incomplete volumes almost never serve any purpose. Boolean.
         */
        public final static String KEEP_BROKEN_VOLUME = PFX + "keepbrokenvolume";
        /**
         * Label the next created volume should have. Can be any text up to 15
         * characters long. Default is &quot;&quot;. String.
         */
        public final static String LABEL = PFX + "label";
        /**
         * Whether an invalidated volume should also be deleted. Boolean.
         */
        public final static String DELETE_AFTER = PFX + "deleteafter";
        /**
         * If the volume should be made for VeraCrypt. Boolean.
         */
        public final static String FOR_VERACRYPT = PFX + "forveracrypt";
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Setup information for construction time. Originally designed for the
     * command line instance, later on extended for the GUI, but it can also
     * be prepared in a way where there are no global things used at all, for
     * example to run a transient instance for volume creation in a server.
     */
    public static class Setup extends Struct {
        private static final long serialVersionUID = -2282480478224342653L;

        /**
         * If loading the properties failed reset them (true) in a way such as
         * there were none provided.
         */
        public boolean resetOnLoadError;
        /**
         * Whether properties should get stored to the given file when the
         * instance gets destroyed.
         */
        public boolean saveProperties;
        /**
         * True if the instance is the one and only for the command line
         * version of TruPax. In this case the volume name (and maybe objects
         * for adding) has to be declared in the arguments.
         */
        public boolean fromCommandLine;
        /**
         * Desired (initial) operation. Only interesting for command line style
         * application, where the syntax of the arguments is determined by what
         * should be done how.
         */
        public InitOp initOp = InitOp.DEFAULT;
        /** Initial operation types. */
        public enum InitOp {
            /** Default (original) operation (create a volume). */
            DEFAULT,
            /** Wipe the given objects (only, nothing else). */
            WIPE,
            /** Extract the given volume to a target directory. */
            EXTRACT,
            /** Invalidate the given volume. */
            INVALIDATE
        }
        /**
         * Flag to cause an attempt to load properties from the file.
         */
        public boolean propFileExists;
        /**
         * The properties file, a common file path and name. Set it to null if
         * no such file can be provided.
         */
        public String propertiesFile;
        /**
         * Command line arguments. Can be null or empty.
         */
        public String[] args;
        /**
         * Notification callback. Can be null.
         */
        public Callbacks cb;
        /** Callback for setup notifications. */
        public interface Callbacks {
            /**
             * Called when the properties got all loaded from file. This is
             * helpful if the caller depends on configuration related
             * information e.g. about what localization settings to use.
             */
            void onProps();
            /**
             * Called if the properties got reset due to a load error, This
             * might be helpful to signal to the user what went wrong.
             * @param err The original (and later suppressed) load error.
             */
            void onLoadErrorReset(Result err);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Constructor. To be called once on a new instance.
     * @param props The properties to use.
     * @param setup All things needed for setup.
     * @return Result of the operation.
     */
    public abstract Result ctor(Properties props, Setup setup);

    /**
     * Destroys the instance (do not access it afterwards). Mainly used to
     * store properties in the file given during construction or in the setup
     * passed then respectively.
     * @return Result of the operation.
     */
    public abstract Result dtor();

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Stores information about a property. Allows determination at run-time,
     * e.g. in a generic configuration editor where not just all values should
     * be accepted blindly from the user.
     */
    public static class PropertyInfo extends Struct {
        private static final long serialVersionUID = -6845578646901357997L;

        /** The data type of a property value. */
        public enum Type {
            /** Boolean flag (stored as "true" or "false"). */
            FLAG,
            /** Signed (integer or long) number. */
            NUMBER,
            /** Arbitrary string. */
            STRING,
            /** Selection of strings. Only the selected string gets stored. */
            SELECT
        }

        /** Type information about the value. */
        public Type type;

        /** For numbers of a certain range: minimum value (inclusive). For
         * everything else this is null. */
        public Long min;

        /** For numbers of a certain range: maximum value (inclusive). For
         * everything else this is null. */
        public Long max;

        /** For numbers with distinct intervals: the step value. For everything
         * else this is null. */
        public Long step;

        /** Selection as arbitrary strings. Null if not of a selection type . */
        public String[] selection;

        /** The default value of the property, as a string. */
        public String dflt;

        public PropertyInfo(Type type, String dflt) {
            this.type = type;
            this.dflt = dflt;
        }
    }

    /**
     * Gets the value of a property. If the property hasn't been set before the
     * default value will be returned.
     * @param name Name of the property to get.
     * @return The property value or null if no such property exists.
     */
    public abstract String getProperty(String name);

    /**
     * Gets information about a property.
     * @param name The name of the property to query information about.
     * @return Property information or null if no such property exists.
     */
    public abstract PropertyInfo getPropertyInfo(String name);

    /**
     * Sets a property. The value will also be verified.
     * @param prop Name and value of the property to set.
     * @return Result of this operation.
     */
    public abstract Result setProperty(NamedString prop);

    /**
     * Verifies a property, but doesn't set it. This is useful to check the
     * user input before even attempting to change anything, or to simply see
     * if a configuration is valid.
     * @param prop Name and new attempted value of the property.
     * @return Result of this operation.
     */
    public abstract Result verifyProperty(NamedString prop);

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Registration of new objects yields this information. Notice that these
     * are always the totals of what is registered, not what was achieved during
     * the last registration cycle.
     */
    public static class RegSum extends Struct {
        private static final long serialVersionUID = 7974246310119390274L;

        /** Number of files which are registered now. */
        public int numberOfFiles;
        /** Number of directories which are registered now. These are the
         * directories as they will appear on the volume. */
        public int numberOfDirectories;
        /** Number of bytes of all files together. This is nice (and maybe even
         * useful) to know, but remember that due to encryption and file system
         * overhead the actually volume size is always bigger. And the more and
         * smaller the files the bigger this overhead actually becomes. */
        public long bytesTotal;
    }

    /** Callback invoked during the registration process. */
    public interface RegisterObjectsCallbacks {
        /**
         * Called when a directory was found.
         * @param dir The absolute path of the directory.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onDirectory(String dir);

        /**
         * Invoked if the (some) configuration is locked for the current
         * registered material. Any further changes won't be honored until the
         * registration gets cleared.
         */
        public void onConfigLocked();
    }

    /** Base for callbacks reporting files. Aborting operation is not supported
     * here by design (not granular enough). */
    @FunctionalInterface
    public interface FileCallback {
        /**
         * Some file was encountered.
         * @param fileName Name of the file (full path).
         * @param fileSize Size of the file in bytes.
         */
        public void onFile(String fileName, long fileSize);
    }

    /** Callback for the volume make process. */
    public interface MakeCallback extends FileCallback {
        /**
         * Called if all files have been written and if the writing of free
         * space data is about to start. This only happens if the amount of
         * free space data is not zero.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onFreeSpace();

        /**
         * Called if the volume was written to. Together with the expected
         * volume size this can be used to provide precise progress reporting.
         * @param pos New write position in bytes.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onVolumeWrite(long pos);

        /**
         * Called if the key generation started, since this might take a while.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onKeyGen();
    }

    /** To report some issue during an operation. */
    public enum Concern {
        /** Something got skipped. For instance a file could not be wiped */
        SKIP(NLS.PRGIMPL_CONCERN_SKIP),
        /** Something exists already and overwriting it might be a problem .*/
        EXISTS(NLS.PRGIMPL_CONCERN_EXISTS),
        /** Some less concerning problem occurred. */
        WARNING(NLS.PRGIMPL_CONCERN_WARNING),
        /** An error occurred. */
        ERROR(NLS.PRGIMPL_CONCERN_ERROR);
        Concern(NLS.Str str) {
            this.str = str;
        }
        NLS.Str str;
        /**
         * Get the localized presentation, suitable to show it to a user.
         * @return The concern as text. One line.
         */
        public String localized() {
            return this.str.s();
        }
    }

    /** Callback invoked whenever an issue occurred and the user should be
     * asked whether continuing the operation is desirable. */
    @FunctionalInterface
    public interface ConcernCallback {
        /**
         * Called if a concern is raised.
         * @param concern The concern.
         * @param message The (localized) message about what is happening.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onConcern(Concern concern, String message);
    }

    /** Generic progress callback. */
    @FunctionalInterface
    public interface ProgressCallback {
        /**
         * Progress has been made. Granularity depends on the implementation.
         * @param percent Percent done so far.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onProgress(double percent);
    }

    /** Callback invoked during a wipe operation. */
    public interface WipeCallback extends ConcernCallback, FileCallback, ProgressCallback {
    }

    /** Callback invoked during an extract operation. Notice that there is no
     * linear progress information available, since the volume gets walked in
     * one pass, so single files are the given granularity. */
    public interface ExtractCallback extends ConcernCallback, FileCallback {
        /**
         * The volume is being opened at this moment. Since this can be a
         * lengthy process (e.g. objects have to be counted first) an occasional
         * update might be beneficial to avoid blocking and provide the chance
         * to stop the extraction before it even started.
         * @param objs Number of objects discovered so far. Purely
         * informational, just to be able to show some non-deterministic
         * progress.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onOpening(int objs);
        /**
         * The volume has been opened successfully.
         * @param files Number of files contained in the volume.
         * @param dirs Number of individual directories in the volume.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onOpen(int files, int dirs);
        /**
         * The currently opened file has been written to.
         * @param pos Number of bytes written to this file so far.
         * @return Whether to continue (OK) or not (ABORTED).
         */
        public Result onFileWrite(long pos);
    }

    /**
     * Sets the volume file to create.
     * @param file Complete file path of the volume file.
     * @return Result of the operation.
     */
    public abstract Result setVolumeFile(String file);

    /**
     * Sets the amount of free space the volume should have. Remember that this
     * space is on block size border (512 bytes), so any remainder will be
     * ignored. The free space will be written as all-zero blocks.
     * @param sz Size of free space in bytes.
     * @return Result of the operation.
     */
    public abstract Result setFreeSpace(long sz);

    /**
     * Add an object to the collection of files and directories to be copied
     * into the volume. Notice that this does not start the actual registration
     * process yet. It is just to get the list together, similar to the stage
     * when passing the list of objects on the command line.
     * @param obj The object to add. Can both be a single file or a directory.
     * Latter will be searched recursively if Prop.RECURSIVE_SEARCH is set to
     * true. Windows-style wild-cards are supported (* and ? masking).
     * @return Result of the operation.
     */
    public abstract Result addObject(String obj);

    /**
     * Clears the whole collection of files and directories which have been
     * added so far. This does not clear the registered data.
     * @return Result of the operation.
     */
    public abstract Result clearObjects();

    /**
     * Register all of the objects added so far.
     * @param cb The registration callback for progress reporting and
     * possible cancellation.
     * @return Result of the operation.
     */
    public abstract Result registerObjects(RegisterObjectsCallbacks cb);

    /**
     * Provides a summary of what got registered.
     * @return Registration summary.
     */
    public abstract RegSum registerSummary();

    /**
     * Clears all of the registered data. One can actually commence to create a
     * volume after this call, it will just be plain empty (with optional free
     * space if it was set up this way).
     * @return Result of the operation.
     */
    public abstract Result registerClear();

    /**
     * Provides the number of objects registered. This is mostly interesting
     * for a view where a list of such is presented (and the actual number of
     * entries must be known, some classical example for that are virtual list
     * views).
     * @return Number of registered entries.
     */
    public abstract int registerViewCount();

    /**
     * Sorts the internal view of the registered material.
     * @param sort Sort type.
     * @param ascending True if sorting should happening ascending, otherwise
     * descending.
     */
    public abstract void registerViewSort(RegObj.Sort sort, boolean ascending);

    /**
     * Provides a portion (or all) of the view of registered entries.
     * @param from Start index of the portion.
     * @param to End index of the view (exclusive, must be smaller than the
     * view count).
     * @return Result of the operation.
     */
    public abstract RegObj[] registerView(int from, int to);

    /**
     * Resolves the volume layout based on the currently registered material.
     * This is usually a fairly quick computation or an efficient dry-run of
     * what is the actually creation process. If this call is successful the
     * volume size can be queried.
     * @return Result of the operation.
     */
    public abstract Result resolve();

    /**
     * Provides the size of the volume which would be created given the
     * currently registered material. You must call resolve() first to compute
     * this value. If new material gets registered you have to resolve again
     * to get the updated value.
     * @return Volume-to-be size, in bytes.
     */
    public abstract long volumeBytes();

    /**
     * Creates the volume.
     * @param password The encryption password. Any length, any characters.
     * @param cb The callback for progress reporting and possible cancellation.
     * @return Result of the operation.
     */
    public abstract Result make(char[] password, MakeCallback cb);

    /**
     * Wipes (securely erases) the currently registered material.
     * @param cb The progress callback. Also used to resolve concerns if
     * something doesn't want to be wiped, or to cancel the operation.
     * @return Result of the operation.
     */
    public abstract Result wipe(WipeCallback cb);

    /**
     * Extracts the currently set volume to the given target directory. It will
     * create a directory identical to the one of the volume. File dates will
     * also be set to what was stored during creation time.
     * @param password The password to open the volume and to decrypt the files
     * and directories it contains.
     * @param dir The extraction directory. Must exist.
     * @param cb Callback for progress reporting, concern resolution and
     * (optional) cancellation.
     * @return Result of the operation.
     */
    public abstract Result extract(char[] password, String dir, ExtractCallback cb);

    /**
     * Invalidates the given volume, meaning the headers are overwritten with
     * arbitrary data, hence making decryption impossible since this also
     * destroys the actual key. Optionally the volume file gets deleted.
     * @param cb Progress callback with the possibility to cancel.
     * @return Result of the operation.
     */
    public abstract Result invalidate(ProgressCallback cb);

    /**
     * Adds additional seed to the secure random number generator.
     * @param seed The extra seed value.
     */
    public abstract void addRandomSeed(long seed);
}

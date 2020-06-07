# TruPax

TruPax generates [VeraCrypt](https://veracrypt.codeplex.com) and TrueCrypt
compatible containers from arbitrary sets of files and folders. Such files match
exactly the size of the contained material and can be mounted via TrueCrypt, but
also directly extracted by TruPax itself. Latter also works for containers
formatted with FAT32 by TrueCrypt itself (thanks to
[fat32-lib](https://github.com/waldheinz/fat32-lib)). For all of that there are
no administrator rights required when using TruPax.

The generated file system of the containers is UDF 1.02, which is supported by
all of the modern operating systems. Most of them also support writing -
meaning files in a container can also be deleted or new ones added. TruPax also
wipes files after container generation, or just as a separate action. You also
invalidate any TrueCrypt container with it very quickly.

TruPax is written in Java 8.

Next to the SWT UI there is also a command line version, and with it TruPax can
be used in fully automated scenarios.

TruPax works fast and also uses all available CPU cores. Containers get
generated in just one pass.

The software is free to use and the source code available under the terms of
the GPLv3. TruPax is a completely independent implementation of the TrueCrypt
logic and shares not a single line of code with latter.

If you want to use the TruPax technology in your own applications, the API is
the right starting point.

## Development

TruPax development is done in Eclipse (Photon+). Choose the right SWT project for
your platform, and import it into your workspace. It will show up as
*org.clipse.swt*. On Linux for instance it would be *swt/4.8/gtk-linux_x86_64/*.
You also need the library [CLBaseLib](https://github.com/mhahn-c/clbaselib), which
you can clone from GitHub and import its Eclipse project.

You should then able to build the code base. Once this has been set up you can
launch the GUI by debugging the class *coderslagoon.trupax.exe.GUI*.

## Testing

Verification for TruPax and CLBaseLib is implemented as JUnit tests, which are
partially functional. Meaning they do interact with the local file system, and
thus run in an authentic manner. All testing material though is created in the
temporary directory, no changes to your machine will be made except in there.
You can run these test cases by simply clicking on the test source folders and
run them as JUnit tests. The whole set of tests should then execute, a full test
run usually takes a few minutes, hence some patience is required.

The test cases can also leverage a third party UDF validation tool, called
*udf_test*, which can be obtained by Phillips. You need to download this tool
yourself, due to licensing it cannot be included in the code base. The *udf_test*
software seems to keep moving around, so it might be tricky to find it. Once
you acquired it point to the *udf_test* executable via the environment variable
*udftestpath*. Under Linux for instance you'd set it to something like
*/opt/udfct1.5r4/bin/linux-noscsi/udf_test*. The TruPax test cases will then
detect its presence and do additional verification steps, to ensure the rendered
UDF file systems comply to the actual specification.

## Shipping

For shipping clone the [jre-reduce](https://github.com/mhahn-c/jre-reduce)
repo from GitHub, in parallel to the other projects. Download the appropriate JRE
runtime files, as mentioned in the jre-reduce documentation. Then run *build.sh*
and *build_macos.sh* to create the installer, passing them a version string.

## I18N

TruPax supports multiple languages and is able to switch between them at
runtime. For new features requiring user visibility (most of them do) both
English and German text resources have to be provided.

I18N is achieved by string definitions and exchangeable resources. Have a look
at the *coderslagoon.trupax.exe.NLS...* files, to see how the mapping works. In a
nutshell: (format) strings are retrieved in the code via the NLS classes, or
their public fields respectively, and in case of a language switch these strings
are re-loaded from the associated resources files. Missing resources will cause
an exception at runtime, so please always do test new textual things in all
available languages - also watch out for correct format parameter provisioning.

## SDK

The SDK comprises two APIs:

* *coderslagoon.trupax.lib.prg.Prg(Impl)* -
  the official TruPax API, as used by the GUI and the command line versions
* *coderslagoon.tclib* -
  low-level functionality, for crypto and raw container handling

Both parts are thoroughly covered with Javadoc, you can create them easily in
Eclipse via *Project..Generate Javadoc*. The best way to learn about the usage
though is to look at the samples:

* *coderslagoon.trupax.sdk.demos* - various examples on how to use the API
* *coderslagoon.trupax.sdk.apps*  - command line apps based on the low-level API

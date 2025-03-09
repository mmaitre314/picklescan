import struct
import zipfile

# More forgiving implementation of zipfile.ZipFile
_FH_SIGNATURE = 0
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = b"PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)


class RelaxedZipFile(zipfile.ZipFile):
    def open(self, name, mode="r", pwd=None, *, force_zip64=False):
        # near copy of zipfile.ZipFile.open with
        """Return file-like object for 'name'.

        name is a string for the file name within the ZIP file, or a ZipInfo
        object.

        mode should be 'r' to read a file already in the ZIP file, or 'w' to
        write to a file newly added to the archive.

        pwd is the password to decrypt files (only used for reading).

        When writing, if the file size is not known in advance but may exceed
        2 GiB, pass force_zip64 to use the ZIP64 format, which can handle large
        files.  If the size is known in advance, it is best to pass a ZipInfo
        instance for name, with zinfo.file_size set.
        """
        if mode not in {"r", "w"}:
            raise ValueError('open() requires mode "r" or "w"')
        if pwd and not isinstance(pwd, bytes):
            raise TypeError("pwd: expected bytes, got %s" % type(pwd).__name__)
        if pwd and (mode == "w"):
            raise ValueError("pwd is only supported for reading files")
        if not self.fp:
            raise ValueError("Attempt to use ZIP archive that was already closed")

        # Make sure we have an info object
        if isinstance(name, zipfile.ZipInfo):
            # 'name' is already an info object
            zinfo = name
        elif mode == "w":
            zinfo = zipfile.ZipInfo(name)
            zinfo.compress_type = self.compression
            zinfo._compresslevel = self.compresslevel
        else:
            # Get info object for name
            zinfo = self.getinfo(name)

        if mode == "w":
            return self._open_to_write(zinfo, force_zip64=force_zip64)

        if self._writing:
            raise ValueError(
                "Can't read from the ZIP file while there "
                "is an open writing handle on it. "
                "Close the writing handle before trying to read."
            )

        # Open for reading:
        self._fileRefCnt += 1
        zef_file = zipfile._SharedFile(
            self.fp,
            zinfo.header_offset,
            self._fpclose,
            self._lock,
            lambda: self._writing,
        )
        try:
            # Skip the file header:
            fheader = zef_file.read(sizeFileHeader)
            if len(fheader) != sizeFileHeader:
                raise zipfile.BadZipFile("Truncated file header")
            fheader = struct.unpack(structFileHeader, fheader)
            if fheader[_FH_SIGNATURE] != stringFileHeader:
                raise zipfile.BadZipFile("Bad magic number for file header")

            zef_file.read(fheader[_FH_FILENAME_LENGTH])
            if fheader[_FH_EXTRA_FIELD_LENGTH]:
                zef_file.read(fheader[_FH_EXTRA_FIELD_LENGTH])

            return zipfile.ZipExtFile(zef_file, mode, zinfo, pwd, True)
        except BaseException:
            zef_file.close()
            raise

//
// Created by Rakeeb Hossain on 2023-04-08.
//
/*
**
 * This is an in-memory VFS implementation that uses an application-supplied
 * virtual memory address. This can be mmap'd ahead of time.
**
** Shared memory is implemented using the usual os_unix VFS, so WAL is enabled
** and can be used.
                                                       **
                                                               ** USAGE:
**
**    sqlite3_open_v2("file:/whatever?ptr=0xf05538&sz=14336&max=65536", &db,
**                    SQLITE_OPEN_READWRITE | SQLITE_OPEN_URI,
**                    "auroravfs");
**
** These are the query parameters:
**
**    ptr=          The address of the memory buffer that holds the database.
**
**    sz=           The current size the database file
        **
        **    maxsz=        The maximum size of the database.  In other words, the
        **                  amount of space allocated for the ptr= buffer.
                                                                   **
                                                                           **    freeonclose=  If true, then sqlite3_free() is called on the ptr=
**                  value when the connection closes.
**
** The ptr= and sz= query parameters are required.  If maxsz= is omitted,
** then it defaults to the sz= value.  Parameter values can be in either
        ** decimal or hexadecimal.  The filename in the URI is ignored.
*/
#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1
#include <string.h>
#include <assert.h>


/*
** Forward declaration of objects used by this utility
*/
typedef struct sqlite3_vfs AuroraVfs;
typedef struct AuroraFile AuroraFile;

/* Access to a lower-level VFS that (might) implement dynamic loading,
** access to randomness, etc.
*/
#define ORIGVFS(p) ((sqlite3_vfs*)((p)->pAppData))

/* An open file */
struct AuroraFile {
    sqlite3_file base;              /* IO methods */
    sqlite3_int64 sz;               /* Size of the file */
    sqlite3_int64 szMax;            /* Space allocated to aData */
    unsigned char *aData;           /* content of the file */
    int bFreeOnClose;               /* Invoke sqlite3_free() on aData at close */
};

/*
** Methods for AuroraFile
*/
static int auroraClose(sqlite3_file*);
static int auroraRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int auroraWrite(sqlite3_file*,const void*,int iAmt, sqlite3_int64 iOfst);
static int auroraTruncate(sqlite3_file*, sqlite3_int64 size);
static int auroraSync(sqlite3_file*, int flags);
static int auroraFileSize(sqlite3_file*, sqlite3_int64 *pSize);
static int auroraLock(sqlite3_file*, int);
static int auroraUnlock(sqlite3_file*, int);
static int auroraCheckReservedLock(sqlite3_file*, int *pResOut);
static int auroraFileControl(sqlite3_file*, int op, void *pArg);
static int auroraSectorSize(sqlite3_file*);
static int auroraDeviceCharacteristics(sqlite3_file*);
static int auroraShmMap(sqlite3_file*, int iPg, int pgsz, int, void volatile**);
static int auroraShmLock(sqlite3_file*, int offset, int n, int flags);
static void auroraShmBarrier(sqlite3_file*);
static int auroraShmUnmap(sqlite3_file*, int deleteFlag);
static int auroraFetch(sqlite3_file*, sqlite3_int64 iOfst, int iAmt, void **pp);
static int auroraUnfetch(sqlite3_file*, sqlite3_int64 iOfst, void *p);

/*
** Methods for AuroraVfs
*/
static int auroraOpen(sqlite3_vfs*, const char *, sqlite3_file*, int , int *);
static int auroraDelete(sqlite3_vfs*, const char *zName, int syncDir);
static int auroraAccess(sqlite3_vfs*, const char *zName, int flags, int *);
static int auroraFullPathname(sqlite3_vfs*, const char *zName, int, char *zOut);
static void *auroraDlOpen(sqlite3_vfs*, const char *zFilename);
static void auroraDlError(sqlite3_vfs*, int nByte, char *zErrMsg);
static void (*auroraDlSym(sqlite3_vfs *pVfs, void *p, const char*zSym))(void);
static void auroraDlClose(sqlite3_vfs*, void*);
static int auroraRandomness(sqlite3_vfs*, int nByte, char *zOut);
static int auroraSleep(sqlite3_vfs*, int microseconds);
static int auroraCurrentTime(sqlite3_vfs*, double*);
static int auroraGetLastError(sqlite3_vfs*, int, char *);
static int auroraCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64*);

static sqlite3_vfs aurora_vfs = {
        2,                           /* iVersion */
        0,                           /* szOsFile (set when registered) */
        1024,                        /* mxPathname */
        0,                           /* pNext */
        "auroravfs",                    /* zName */
        0,                           /* pAppData (set when registered) */
        auroraOpen,                     /* xOpen */
        auroraDelete,                   /* xDelete */
        auroraAccess,                   /* xAccess */
        auroraFullPathname,             /* xFullPathname */
        auroraDlOpen,                   /* xDlOpen */
        auroraDlError,                  /* xDlError */
        auroraDlSym,                    /* xDlSym */
        auroraDlClose,                  /* xDlClose */
        auroraRandomness,               /* xRandomness */
        auroraSleep,                    /* xSleep */
        auroraCurrentTime,              /* xCurrentTime */
        auroraGetLastError,             /* xGetLastError */
        auroraCurrentTimeInt64          /* xCurrentTimeInt64 */
};

static const sqlite3_io_methods aurora_io_methods = {
        3,                              /* iVersion */
        auroraClose,                      /* xClose */
        auroraRead,                       /* xRead */
        auroraWrite,                      /* xWrite */
        auroraTruncate,                   /* xTruncate */
        auroraSync,                       /* xSync */
        auroraFileSize,                   /* xFileSize */
        auroraLock,                       /* xLock */
        auroraUnlock,                     /* xUnlock */
        auroraCheckReservedLock,          /* xCheckReservedLock */
        auroraFileControl,                /* xFileControl */
        auroraSectorSize,                 /* xSectorSize */
        auroraDeviceCharacteristics,      /* xDeviceCharacteristics */
        auroraShmMap,                     /* xShmMap */
        auroraShmLock,                    /* xShmLock */
        auroraShmBarrier,                 /* xShmBarrier */
        auroraShmUnmap,                   /* xShmUnmap */
        auroraFetch,                      /* xFetch */
        auroraUnfetch                     /* xUnfetch */
};



/*
** Close an aurora-file.
**
** The pData pointer is owned by the application, so there is nothing
** to free.
*/
static int auroraClose(sqlite3_file *pFile){
    AuroraFile *p = (AuroraFile *)pFile;
    if( p->bFreeOnClose ) sqlite3_free(p->aData);
    return SQLITE_OK;
}

/*
** Read data from an aurora-file.
*/
static int auroraRead(
        sqlite3_file *pFile,
        void *zBuf,
        int iAmt,
        sqlite_int64 iOfst
){
    AuroraFile *p = (AuroraFile *)pFile;
    memcpy(zBuf, p->aData+iOfst, iAmt);
    return SQLITE_OK;
}

/*
** Write data to an aurora-file.
*/
static int auroraWrite(
        sqlite3_file *pFile,
        const void *z,
        int iAmt,
        sqlite_int64 iOfst
){
    AuroraFile *p = (AuroraFile *)pFile;
    if( iOfst+iAmt>p->sz ){
        if( iOfst+iAmt>p->szMax ) return SQLITE_FULL;
        if( iOfst>p->sz ) memset(p->aData+p->sz, 0, iOfst-p->sz);
        p->sz = iOfst+iAmt;
    }
    memcpy(p->aData+iOfst, z, iAmt);
    return SQLITE_OK;
}

/*
** Truncate an aurora-file.
*/
static int auroraTruncate(sqlite3_file *pFile, sqlite_int64 size){
    AuroraFile *p = (AuroraFile *)pFile;
    if( size>p->sz ){
        if( size>p->szMax ) return SQLITE_FULL;
        memset(p->aData+p->sz, 0, size-p->sz);
    }
    p->sz = size;
    return SQLITE_OK;
}

/*
** Sync an aurora-file.
*/
static int auroraSync(sqlite3_file *pFile, int flags){
    return SQLITE_OK;
}

/*
** Return the current file-size of an aurora-file.
*/
static int auroraFileSize(sqlite3_file *pFile, sqlite_int64 *pSize){
    AuroraFile *p = (AuroraFile *)pFile;
    *pSize = p->sz;
    return SQLITE_OK;
}

/*
** Lock an aurora-file.
*/
static int auroraLock(sqlite3_file *pFile, int eLock){
    return SQLITE_OK;
}

/*
** Unlock an aurora-file.
*/
static int auroraUnlock(sqlite3_file *pFile, int eLock){
    return SQLITE_OK;
}

/*
** Check if another file-handle holds a RESERVED lock on an aurora-file.
*/
static int auroraCheckReservedLock(sqlite3_file *pFile, int *pResOut){
    *pResOut = 0;
    return SQLITE_OK;
}

/*
** File control method. For custom operations on an aurora-file.
*/
static int auroraFileControl(sqlite3_file *pFile, int op, void *pArg){
    AuroraFile *p = (AuroraFile *)pFile;
    int rc = SQLITE_NOTFOUND;
    if( op==SQLITE_FCNTL_VFSNAME ){
        *(char**)pArg = sqlite3_mprintf("mem(%p,%lld)", p->aData, p->sz);
        rc = SQLITE_OK;
    }
    return rc;
}

/*
** Return the sector-size in bytes for an aurora-file.
*/
static int auroraSectorSize(sqlite3_file *pFile){
    return 1024;
}

/*
** Return the device characteristic flags supported by an aurora-file.
*/
static int auroraDeviceCharacteristics(sqlite3_file *pFile){
    return SQLITE_IOCAP_ATOMIC |
           SQLITE_IOCAP_POWERSAFE_OVERWRITE |
           SQLITE_IOCAP_SAFE_APPEND |
           SQLITE_IOCAP_SEQUENTIAL;
}

/* Create a shared memory file mapping */
static int auroraShmMap(
        sqlite3_file *pFile,
        int iPg,
        int pgsz,
        int bExtend,
        void volatile **pp
){
    return SQLITE_IOERR_SHMMAP;
}

/* Perform locking on a shared-memory segment */
static int auroraShmLock(sqlite3_file *pFile, int offset, int n, int flags){
    return SQLITE_IOERR_SHMLOCK;
}

/* Memory barrier operation on shared memory */
static void auroraShmBarrier(sqlite3_file *pFile){
    return;
}

/* Unmap a shared memory segment */
static int auroraShmUnmap(sqlite3_file *pFile, int deleteFlag){
    return SQLITE_OK;
}

/* Fetch a page of a memory-mapped file */
static int auroraFetch(
        sqlite3_file *pFile,
        sqlite3_int64 iOfst,
        int iAmt,
        void **pp
){
    AuroraFile *p = (AuroraFile *)pFile;
    *pp = (void*)(p->aData + iOfst);
    return SQLITE_OK;
}

/* Release a memory-mapped page */
static int auroraUnfetch(sqlite3_file *pFile, sqlite3_int64 iOfst, void *pPage){
    return SQLITE_OK;
}

/*
** Open an aurora file handle.
*/
static int auroraOpen(
        sqlite3_vfs *pVfs,
        const char *zName,
        sqlite3_file *pFile,
        int flags,
        int *pOutFlags
){
    AuroraFile *p = (AuroraFile*)pFile;
    memset(p, 0, sizeof(*p));
    if( (flags & SQLITE_OPEN_MAIN_DB)==0 ) return SQLITE_CANTOPEN;
    p->aData = (unsigned char*)sqlite3_uri_int64(zName,"ptr",0);
    if( p->aData==0 ) return SQLITE_CANTOPEN;
    p->sz = sqlite3_uri_int64(zName,"sz",0);
    if( p->sz<0 ) return SQLITE_CANTOPEN;
    p->szMax = sqlite3_uri_int64(zName,"max",p->sz);
    if( p->szMax<p->sz ) return SQLITE_CANTOPEN;
    p->bFreeOnClose = sqlite3_uri_boolean(zName,"freeonclose",0);
    pFile->pMethods = &aurora_io_methods;
    return SQLITE_OK;
}

/*
** Delete the file located at zPath. If the dirSync argument is true,
** ensure the file-system modifications are synced to disk before
** returning.
*/
static int auroraDelete(sqlite3_vfs *pVfs, const char *zPath, int dirSync){
    return SQLITE_IOERR_DELETE;
}

/*
** Test for access permissions. Return true if the requested permission
** is available, or false otherwise.
*/
static int auroraAccess(
        sqlite3_vfs *pVfs,
        const char *zPath,
        int flags,
        int *pResOut
){
    *pResOut = 0;
    return SQLITE_OK;
}

/*
** Populate buffer zOut with the full canonical pathname corresponding
** to the pathname in zPath. zOut is guaranteed to point to a buffer
** of at least (INST_MAX_PATHNAME+1) bytes.
*/
static int auroraFullPathname(
        sqlite3_vfs *pVfs,
        const char *zPath,
        int nOut,
        char *zOut
){
    sqlite3_snprintf(nOut, zOut, "%s", zPath);
    return SQLITE_OK;
}

/*
** Open the dynamic library located at zPath and return a handle.
*/
static void *auroraDlOpen(sqlite3_vfs *pVfs, const char *zPath){
    return ORIGVFS(pVfs)->xDlOpen(ORIGVFS(pVfs), zPath);
}

/*
** Populate the buffer zErrMsg (size nByte bytes) with a human readable
** utf-8 string describing the most recent error encountered associated
** with dynamic libraries.
*/
static void auroraDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg){
    ORIGVFS(pVfs)->xDlError(ORIGVFS(pVfs), nByte, zErrMsg);
}

/*
** Return a pointer to the symbol zSymbol in the dynamic library pHandle.
*/
static void (*auroraDlSym(sqlite3_vfs *pVfs, void *p, const char *zSym))(void){
    return ORIGVFS(pVfs)->xDlSym(ORIGVFS(pVfs), p, zSym);
}

/*
** Close the dynamic library handle pHandle.
*/
static void auroraDlClose(sqlite3_vfs *pVfs, void *pHandle){
    ORIGVFS(pVfs)->xDlClose(ORIGVFS(pVfs), pHandle);
}

/*
** Populate the buffer pointed to by zBufOut with nByte bytes of
** random data.
*/
static int auroraRandomness(sqlite3_vfs *pVfs, int nByte, char *zBufOut){
    return ORIGVFS(pVfs)->xRandomness(ORIGVFS(pVfs), nByte, zBufOut);
}

/*
** Sleep for nMicro microseconds. Return the number of microseconds
** actually slept.
*/
static int auroraSleep(sqlite3_vfs *pVfs, int nMicro){
    return ORIGVFS(pVfs)->xSleep(ORIGVFS(pVfs), nMicro);
}

/*
** Return the current time as a Julian Day number in *pTimeOut.
*/
static int auroraCurrentTime(sqlite3_vfs *pVfs, double *pTimeOut){
    return ORIGVFS(pVfs)->xCurrentTime(ORIGVFS(pVfs), pTimeOut);
}

static int auroraGetLastError(sqlite3_vfs *pVfs, int a, char *b){
    return ORIGVFS(pVfs)->xGetLastError(ORIGVFS(pVfs), a, b);
}
static int auroraCurrentTimeInt64(sqlite3_vfs *pVfs, sqlite3_int64 *p){
    return ORIGVFS(pVfs)->xCurrentTimeInt64(ORIGVFS(pVfs), p);
}

/*
** This routine is called when the extension is loaded.
** Register the new VFS.
*/
int sqlite3_auroravfs_init(
        sqlite3 *db,
        char **pzErrMsg,
        const sqlite3_api_routines *pApi
){
    int rc = SQLITE_OK;
    SQLITE_EXTENSION_INIT2(pApi);
    aurora_vfs.pAppData = sqlite3_vfs_find(0);
    if( aurora_vfs.pAppData==0 ) return SQLITE_ERROR;
    aurora_vfs.szOsFile = sizeof(AuroraFile);
    rc = sqlite3_vfs_register(&aurora_vfs, 1);
#ifdef MEMVFS_TEST
    if( rc==SQLITE_OK ){
    rc = sqlite3_auto_extension((void(*)(void))auroravfsRegister);
  }
  if( rc==SQLITE_OK ){
    rc = auroravfsRegister(db, pzErrMsg, pApi);
  }
#endif
    if( rc==SQLITE_OK ) rc = SQLITE_OK_LOAD_PERMANENTLY;
    return rc;
}

/*++

Module Name:

	LRSS.c

Abstract:

	This is the main module of the LRSS miniFilter driver.

Environment:

	Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include "FileList.h"
#include "EncryptionDetector.h"


#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

PLIST_ENTRY activeFilesHead = NULL;
LARGE_INTEGER renameIndexNumber = { 0 };

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
	Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
LRSSUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
LRSSPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
LRSSPreCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
LRSSPreRename(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
LRSSPostRename(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

VOID
LRSSOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
);

BOOLEAN
LRSSDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, LRSSUnload)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 1

	{ IRP_MJ_CLEANUP,
	  FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	  LRSSPreCleanup,
	  NULL },

	{ IRP_MJ_CREATE,
	  FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	  NULL,
	  LRSSPostCreate },

	{ IRP_MJ_SET_INFORMATION,
	  FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	  LRSSPreRename,
	  LRSSPostRename },

#endif

	{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	LRSSUnload,                         //  MiniFilterUnload

	NULL,								//  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,								//  InstanceTeardownStart
	NULL,								//  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for this miniFilter driver.  This
	registers with FltMgr and initializes all global data structures.
	It executes when LRSS is loaded (e.g. from the command line).

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Routine can return non success error codes.

--*/
{
	// global variable initialization
	activeFilesHead = ExAllocatePoolWithTag(PagedPool, sizeof(LIST_ENTRY), 'List');
	InitializeListHead(activeFilesHead);

	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("LRSS!DriverEntry: Entered\n"));

	//  Register with FltMgr to tell it our callback routines

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);

	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status)) {

		//  Start filtering i/o

		status = FltStartFiltering(gFilterHandle);

		if (!NT_SUCCESS(status)) {

			LRSSUnload(FLTFL_FILTER_UNLOAD_MANDATORY);
		}
	}

	return status;
}

NTSTATUS
LRSSUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

	This is the unload routine for this miniFilter driver. This is called
	when the minifilter is about to be unloaded. We can fail this unload
	request if this is not a mandatory unload indicated by the Flags
	parameter.

Arguments:

	Flags - Indicating if this is a mandatory unload.

Return Value:

	Returns STATUS_SUCCESS.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("LRSS!LRSSUnload: Entered\n"));

	// delete all snapshots.

	NTSTATUS status;


	// systematically delete unused snapshot files
	if (activeFilesHead != NULL) {
		PLIST_ENTRY currentEntry = activeFilesHead->Flink;
		PSnapshot currentSnapshot;

		while (currentEntry != activeFilesHead) {

			currentSnapshot = (PSnapshot)CONTAINING_RECORD(currentEntry, snapshot, listEntry);

			HANDLE snapshotHandle = currentSnapshot->file;

			PLIST_ENTRY nextEntry = currentEntry->Flink;

			RemoveEntryList(currentEntry);

			ExFreePoolWithTag(currentSnapshot, 'List');

			currentEntry = nextEntry;

			status = FltClose(snapshotHandle);

			if (!NT_SUCCESS(status)) {
				DbgPrint("%s", "Failed to delete snapshot.");
			}
		}
	}

	// free activeFilesList handle
	ExFreePoolWithTag(activeFilesHead, 'List');

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}

/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/
FLT_POSTOP_CALLBACK_STATUS
LRSSPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

	This routine is a post-create dispatch routine for this miniFilter.

	It executes prior to a file create operation and creates read-only
	snapshots of accessed files when they are opened with write-access.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	//debugging statement
	DbgPrint("%s", "Commencing pre-write routine");

	// only works safely at passive IRQL
	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {

		ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

		// we only want to take snapshots of writes to EXISTING files - snapshots of new files often leads to false positives
		if (Data->Iopb->TargetFileObject->WriteAccess && desiredAccess != FILE_CREATE && desiredAccess != FILE_SUPERSEDE && desiredAccess != FILE_OVERWRITE && desiredAccess != FILE_OVERWRITE_IF) {

			NTSTATUS status;

			FLT_FILE_NAME_INFORMATION *fileNameInfo;

			// get file name
			status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fileNameInfo);

			if (NT_SUCCESS(status)) {

				// prepare structures to open the active file

				UNICODE_STRING fileName = fileNameInfo->Name;
				FltParseFileNameInformation(fileNameInfo);
				OBJECT_ATTRIBUTES objectAttributes;
				IO_STATUS_BLOCK ioStatusBlock;

				InitializeObjectAttributes(
					&objectAttributes,
					&fileName,
					OBJ_KERNEL_HANDLE,
					NULL,
					NULL
				);

				HANDLE activeFileHandle;
				PFILE_OBJECT activeFileObject;

				// attempt to open file
				status = FltCreateFileEx(gFilterHandle, FltObjects->Instance, &activeFileHandle, &activeFileObject, FILE_GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

				//if file in question successfully opened
				if (NT_SUCCESS(status)) {

					// check whether the active file is a directory -> if so, nothing further is required
					BOOLEAN isDirectory;
					status = FltIsDirectory(activeFileObject, FltObjects->Instance, &isDirectory);

					// only proceed if the file is not a directory.
					if (NT_SUCCESS(status) && !isDirectory) {

						// retrieve information about the file
						FILE_INTERNAL_INFORMATION fileInfo;
						status = FltQueryInformationFile(FltObjects->Instance, activeFileObject, &fileInfo, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, NULL);

						//successfully retrieved file information
						if (NT_SUCCESS(status)) {

							//if file not in active files: need to create snapshot and log it in active files list
							if ((activeFilesHead != NULL) && (IsListEmpty(activeFilesHead) || getFile(activeFilesHead, fileInfo.IndexNumber) == NULL)) {

								// create snapshot file

								// snapshot name construction
								UNICODE_STRING snapshotFileName;

								UNICODE_STRING snapshotDirectory;
								RtlInitUnicodeString(&snapshotDirectory, L"\\Snapshots\\");

								snapshotFileName.Buffer = ExAllocatePoolWithTag(PagedPool, fileNameInfo->Volume.Length + fileName.Length + snapshotDirectory.Length, 'snap');
								snapshotFileName.MaximumLength = fileNameInfo->Volume.Length + fileName.Length + snapshotDirectory.Length;
								snapshotFileName.Length = 0;

								RtlCopyUnicodeString(&snapshotFileName, &fileNameInfo->Volume);
								RtlUnicodeStringCat(&snapshotFileName, &snapshotDirectory);
								RtlUnicodeStringCat(&snapshotFileName, &fileNameInfo->FinalComponent);

								// initialized structures for snapshot file creation
								OBJECT_ATTRIBUTES snapshotAttributes;
								InitializeObjectAttributes(&snapshotAttributes, &snapshotFileName, OBJ_KERNEL_HANDLE, NULL, NULL);

								HANDLE snapshotHandle;
								PFILE_OBJECT snapshotFileObject;
								IO_STATUS_BLOCK snapshotCreationStatusBlock;

								// initialize the snapshot to the same size as active file
								LARGE_INTEGER snapshotAllocationSize;
								snapshotAllocationSize.QuadPart = activeFileObject->Size;

								FILE_BASIC_INFORMATION fileBasicInfo;
								status = FltQueryInformationFile(FltObjects->Instance, activeFileObject, &fileBasicInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, NULL);

								if (NT_SUCCESS(status)) {

									// create snapshot file
									status = FltCreateFileEx(gFilterHandle, FltObjects->Instance, &snapshotHandle, &snapshotFileObject, GENERIC_WRITE, &snapshotAttributes, &snapshotCreationStatusBlock, &snapshotAllocationSize, fileBasicInfo.FileAttributes, 0, FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

									if (NT_SUCCESS(status)) {

										// get volume sector size for I/O - this may no longer be necessary
										FLT_VOLUME_PROPERTIES volumeProperties;
										ULONG sectorSize;
										status = FltGetVolumeProperties(FltObjects->Volume, &volumeProperties, sizeof(volumeProperties), &sectorSize);

										if (!NT_ERROR(status)) {

											// if the active file has read access enabled
											if (activeFileObject->ReadAccess) {

												sectorSize = volumeProperties.SectorSize;

												//allocate read buffer
												void* buffer = ExAllocatePoolWithTag(PagedPool, sectorSize, 'PWCP');

												//check successful memory allocation
												if (buffer != NULL) {

													BOOLEAN successfulCopy = TRUE;

													LARGE_INTEGER byteOffset = { 0 };

													// read file and count byte occurrences
													while (TRUE) {

														ULONG bytesRead;

														status = FltReadFile(FltObjects->Instance, activeFileObject, &byteOffset, sectorSize, buffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &bytesRead, NULL, NULL);

														// unsuccessful read -> check for expected error, otherwise conservatively return unencrypted
														if (!NT_SUCCESS(status)) {
															if (status == STATUS_END_OF_FILE) {
																break;
															}
															// unexpected error code
															else {
																successfulCopy = FALSE;
																break;
															}
														}
														// successful read -> write buffer contents to snapshot
														else {
															ULONG bytesWritten;

															status = FltWriteFile(FltObjects->Instance, snapshotFileObject, &byteOffset, bytesRead, buffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &bytesWritten, NULL, NULL);

															if (!NT_SUCCESS(status)) {
																successfulCopy = FALSE;
																break;
															}
														}

														// extra error check
														if (bytesRead < sectorSize) {
															break;
														}

														// update read offset 
														byteOffset.QuadPart += bytesRead;
													}

													// if copy was successful, add snapshot to file list
													if (successfulCopy) {

														// make snapshot read-only
														fileBasicInfo.FileAttributes = fileBasicInfo.FileAttributes | FILE_ATTRIBUTE_READONLY;
														FltSetInformationFile(FltObjects->Instance, snapshotFileObject, &fileBasicInfo, sizeof(fileBasicInfo), FileBasicInformation);

														// add to active files list
														addFile(activeFilesHead, fileInfo.IndexNumber, snapshotHandle);

													}
													// otherwise, delete snapshot file
													else {
														if (snapshotHandle != NULL && snapshotFileObject != NULL) {
															FltClose(snapshotHandle);
														}
													}

													// free file read/write buffer
													if (buffer != NULL) {
														ExFreePoolWithTag(buffer, 'PWCP');
														buffer = NULL;
													}
												}
												else {
													if (snapshotHandle != NULL && snapshotFileObject != NULL) {
														FltClose(snapshotHandle);
													}
												}
											}
										}
										else {
											if (snapshotHandle != NULL && snapshotFileObject != NULL) {
												FltClose(snapshotHandle);
											}
										}
									}
									else {
										if (snapshotHandle != NULL && snapshotFileObject != NULL) {
											FltClose(snapshotHandle);
										}
									}
								}
								ExFreePoolWithTag(snapshotFileName.Buffer, 'snap');
							}
						}
					}
					// done with active file
					FltClose(activeFileHandle);
				}
				// free file name buffer
				FltReleaseFileNameInformation(fileNameInfo);
			}
		}
	}
	// return with okay to continue with requested I/O
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
LRSSPreCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine is a pre-cleanup dispatch routine for this miniFilter.

This routine executes when the last handle to a file is closed.

It checks whether the closed file has an associated snapshot,
then examines the contents of the file and its snapshot to
determine whether the file was encrypted.

If the file was encrypted, the snapshot is copied to the same directory
in case the file was encrypted by ransomware.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("LRSS!LRSSPreOperation: Entered\n"));

	// can only safely operate at passive IRQL
	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {

		// first check whether we have any snapshots
		if (activeFilesHead != NULL && !IsListEmpty(activeFilesHead)) {

			BOOLEAN isDirectory;

			NTSTATUS status;
			status = FltIsDirectory(Data->Iopb->TargetFileObject, FltObjects->Instance, &isDirectory);

			// only perform further processing if the target file is not a directory
			if (NT_SUCCESS(status) && !isDirectory) {

				// we have snapshots, so we need to check for a match with the active file
				FILE_INTERNAL_INFORMATION fileInfo;
				status = FltQueryInformationFile(FltObjects->Instance, Data->Iopb->TargetFileObject, &fileInfo, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, NULL);

				// successful query for file information?
				if (NT_SUCCESS(status)) {

					FILE_BASIC_INFORMATION fileBasicInfo;
					status = FltQueryInformationFile(FltObjects->Instance, Data->Iopb->TargetFileObject, &fileBasicInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, NULL);

					if (NT_SUCCESS(status)) {

						// check active file list for matching key
						HANDLE snapshotHandle = removeFile(activeFilesHead, fileInfo.IndexNumber);

						// snapshot found
						if (snapshotHandle != NULL) {

							// attempt to retrieve FILE_OBJECT from HANDLE
							PVOID snapshotObjectVoid;
							status = ObReferenceObjectByHandle(snapshotHandle, GENERIC_READ, *IoFileObjectType, KernelMode, &snapshotObjectVoid, NULL);

							// successful retrieval of file object?
							if (NT_SUCCESS(status)) {

								PFILE_OBJECT snapshotObject = (PFILE_OBJECT)snapshotObjectVoid;

								// retrieve volume sector size for non-cached I/O
								FLT_VOLUME_PROPERTIES volumeProperties;
								ULONG sectorSize;
								status = FltGetVolumeProperties(FltObjects->Volume, &volumeProperties, sizeof(volumeProperties), &sectorSize);

								if (!NT_ERROR(status)) {

									// check whether active file looks encrypted
									BOOLEAN fileIsEncrypted = isEncrypted(Data->Iopb->TargetFileObject, FltObjects->Instance, sectorSize);

									if (fileIsEncrypted == TRUE) {

										PFLT_FILE_NAME_INFORMATION fileNameInfo;
										status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fileNameInfo);

										if (NT_SUCCESS(status)) {

											// parse target file name information
											status = FltParseFileNameInformation(fileNameInfo);

											if (NT_SUCCESS(status)) {

												// retrieve target file's parent directory to place replacement file in
												HANDLE targetFileParentDirHandle;
												OBJECT_ATTRIBUTES targetFileParentDirAttributes;
												IO_STATUS_BLOCK targetFileParentDirStatusBlock;

												UNICODE_STRING parentDirectoryFullPath;
												parentDirectoryFullPath.Buffer = ExAllocatePoolWithTag(PagedPool, (fileNameInfo->Volume.Length + fileNameInfo->ParentDir.Length), 'pdir');
												parentDirectoryFullPath.Length = 0;
												parentDirectoryFullPath.MaximumLength = fileNameInfo->Volume.Length + fileNameInfo->ParentDir.Length;

												RtlCopyUnicodeString(&parentDirectoryFullPath, &(fileNameInfo->Volume));
												RtlUnicodeStringCat(&parentDirectoryFullPath, &(fileNameInfo->ParentDir));

												InitializeObjectAttributes(&targetFileParentDirAttributes, &parentDirectoryFullPath, OBJ_KERNEL_HANDLE, NULL, NULL);
												status = FltCreateFile(gFilterHandle, FltObjects->Instance, &targetFileParentDirHandle, FILE_TRAVERSE | FILE_LIST_DIRECTORY, &targetFileParentDirAttributes, &targetFileParentDirStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

												if (NT_SUCCESS(status)) {

													ExFreePoolWithTag(parentDirectoryFullPath.Buffer, 'pdir');

													LARGE_INTEGER replacementFileAllocationSize;
													replacementFileAllocationSize.QuadPart = snapshotObject->Size;

													//Create new file to copy snapshot to
													HANDLE replacementFileHandle;
													PFILE_OBJECT replacementFileObject;
													OBJECT_ATTRIBUTES replacementFileObjectAttributes;
													
													UNICODE_STRING snapshotPrefix;
													RtlInitUnicodeString(&snapshotPrefix, L"Snapshot-");

													UNICODE_STRING snapshotExtension;
													RtlInitUnicodeString(&snapshotExtension, L".lrs");

													UNICODE_STRING snapshotFileNameFinalComponent;
													status = FltParseFileName(&(snapshotObject->FileName), NULL, NULL, &snapshotFileNameFinalComponent);

													// check for successful parse of file name
													if (NT_SUCCESS(status)) {

														UNICODE_STRING snapshotFileNameComplete;
														snapshotFileNameComplete.Buffer = ExAllocatePoolWithTag(PagedPool, snapshotPrefix.Length + snapshotFileNameFinalComponent.Length + snapshotExtension.Length, 'name');
														snapshotFileNameComplete.Length = 0;
														snapshotFileNameComplete.MaximumLength = snapshotPrefix.Length + snapshotFileNameFinalComponent.Length + snapshotExtension.Length;
														RtlCopyUnicodeString(&snapshotFileNameComplete, &snapshotPrefix);
														RtlUnicodeStringCat(&snapshotFileNameComplete, &snapshotFileNameFinalComponent);
														RtlUnicodeStringCat(&snapshotFileNameComplete, &snapshotExtension);

														InitializeObjectAttributes(&replacementFileObjectAttributes, &(snapshotFileNameComplete), OBJ_KERNEL_HANDLE, targetFileParentDirHandle, NULL);
														IO_STATUS_BLOCK replacementFileStatusBlock;

														// query for snapshot basic info to retrieve file attributes
														FILE_BASIC_INFORMATION snapshotBasicInfo;
														status = FltQueryInformationFile(FltObjects->Instance, snapshotObject, &snapshotBasicInfo, sizeof(snapshotBasicInfo), FileBasicInformation, NULL);

														// check successful query
														if (NT_SUCCESS(status)) {

															//create replacement file
															status = FltCreateFileEx(gFilterHandle, FltObjects->Instance, &replacementFileHandle, &replacementFileObject, GENERIC_WRITE, &replacementFileObjectAttributes, &replacementFileStatusBlock, &replacementFileAllocationSize, fileBasicInfo.FileAttributes, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

															ExFreePoolWithTag(snapshotFileNameComplete.Buffer, 'name');

															if (NT_SUCCESS(status)) {


																LARGE_INTEGER byteOffset = { 0 };
																PVOID buffer = ExAllocatePoolWithTag(PagedPool, sectorSize, 'PCCP');

																if (buffer != NULL) {

																	BOOLEAN successfulCopy = TRUE;

																	// read snapshot and write to replacement file
																	while (TRUE) {

																		ULONG bytesRead;

																		status = FltReadFile(FltObjects->Instance, snapshotObject, &byteOffset, sectorSize, buffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &bytesRead, NULL, NULL);

																		// unsuccessful read -> check for expected error, otherwise conservatively exit copy
																		if (!NT_SUCCESS(status)) {
																			if (status == STATUS_END_OF_FILE) {
																				break;
																			}
																			// unexpected error code
																			else {
																				successfulCopy = FALSE;
																				break;
																			}
																		}
																		// successful read -> write to replacement file
																		else {
																			ULONG bytesWritten;

																			status = FltWriteFile(FltObjects->Instance, replacementFileObject, &byteOffset, bytesRead, buffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &bytesWritten, NULL, NULL);

																			if (!NT_SUCCESS(status)) {
																				successfulCopy = FALSE;
																				break;
																			}
																		}

																		// extra error check
																		if (bytesRead < sectorSize) {
																			break;
																		}

																		// update read offset 
																		byteOffset.QuadPart += bytesRead;

																	}
																	if (buffer != NULL) {
																		ExFreePoolWithTag(buffer, 'PCCP');
																		buffer = NULL;
																	}
																}
																FltClose(replacementFileHandle);
															}
														}
													}
													FltClose(targetFileParentDirHandle);
												}
											}
											FltReleaseFileNameInformation(fileNameInfo);
										}

									}
								}
							}
							status = FltClose(snapshotHandle);

							if (!NT_SUCCESS(status)) {
								DbgPrint("%s", "Unable to delete snapshot.\n");
							}
						}
					}
				}
			}
		}
	}

	// always allow file cleanup to proceed - we've set the target file to be deleted, so this should complete the task.
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
LRSSPreRename(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine is a pre-rename dispatch routine for this miniFilter.

The purpose of this routine is to update the active files list to be resilient to file renames,
which is a common aspect of ransomware behaviour. Most variants do not preserve the name of the file.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(CompletionContext);

	// first check whether we have any snapshots - nothing to do if not.
	if (activeFilesHead != NULL && !IsListEmpty(activeFilesHead)) {

		// only need to act if this operation is a file rename
		if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {

			// retrieve file index number to use as key
			FILE_INTERNAL_INFORMATION fileInfo;
			ULONG bytesReturned;
			NTSTATUS status = FltQueryInformationFile(FltObjects->Instance, Data->Iopb->TargetFileObject, &fileInfo, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, &bytesReturned);

			// if key successfully obtained, compare to keys of snapshots
			if (NT_SUCCESS(status) && bytesReturned > 0) {
				HANDLE fileHandle = getFile(activeFilesHead, fileInfo.IndexNumber);

				// if we find a matching snapshot, update global variable to be checked
				// by post-rename routine
				if (fileHandle != NULL) {
					renameIndexNumber = fileInfo.IndexNumber;
					return FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}
			}
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
LRSSPostRename(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

This routine is a post-rename dispatch routine for this miniFilter.

This is non-pageable because it could be called on the paging path

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	// if the renameIndexNumber variable was set by the pre-rename routine,
	// we need to update the key of a snapshot.
	if (renameIndexNumber.QuadPart != 0) {

		// query for key value
		FILE_INTERNAL_INFORMATION fileInfo;
		ULONG bytesReturned;
		NTSTATUS status = FltQueryInformationFile(FltObjects->Instance, Data->Iopb->TargetFileObject, &fileInfo, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, &bytesReturned);

		// if query successful, update the key of the renamed file's snapshot
		if (NT_SUCCESS(status) && bytesReturned > 0) {
			updateKey(activeFilesHead, renameIndexNumber, fileInfo.IndexNumber);
		}

		// reset variable to 0
		renameIndexNumber.QuadPart = 0;
		renameIndexNumber.LowPart = 0;
		renameIndexNumber.HighPart = 0;
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}



VOID
LRSSOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
)
/*++

Routine Description:

	This routine is called when the given operation returns from the call
	to IoCallDriver.  This is useful for operations where STATUS_PENDING
	means the operation was successfully queued.  This is useful for OpLocks
	and directory change notification operations.

	This callback is called in the context of the originating thread and will
	never be called at DPC level.  The file object has been correctly
	referenced so that you can access it.  It will be automatically
	dereferenced upon return.

	This is non-pageable because it could be called on the paging path

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	RequesterContext - The context for the completion routine for this
		operation.

	OperationStatus -

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("LRSS!LRSSOperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("LRSS!LRSSOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
			OperationStatus,
			RequesterContext,
			ParameterSnapshot->MajorFunction,
			ParameterSnapshot->MinorFunction,
			FltGetIrpName(ParameterSnapshot->MajorFunction)));
}

FLT_PREOP_CALLBACK_STATUS
LRSSPreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

	This routine is a pre-operation dispatch routine for this miniFilter.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("LRSS!LRSSPreOperationNoPostOperation: Entered\n"));

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
LRSSDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

	This identifies those operations we want the operation status for.  These
	are typically operations that return STATUS_PENDING as a normal completion
	status.

Arguments:

Return Value:

	TRUE - If we want the operation status
	FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

			||

			//
			//    Check for directy change notification
			//

			((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
			(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
			);
}

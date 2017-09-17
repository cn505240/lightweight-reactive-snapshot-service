/*++
Header file for the file list structure for tracking active files
Author: Conor McLaughlin
Data: May 26, 2017
--*/

#include <fltKernel.h>

#ifndef FILE_LIST_H
#define FILE_LIST_H


//fileList node structure
typedef struct _SNAPSHOTSTRUCT {
	LIST_ENTRY listEntry;
	LARGE_INTEGER key;
	HANDLE file;
} snapshot, *PSnapshot;

//Creates a new file entry and inserts to the correct position in the list
void addFile(PLIST_ENTRY list, LARGE_INTEGER key, HANDLE data);
HANDLE getFile(PLIST_ENTRY list, LARGE_INTEGER key);
void updateKey(PLIST_ENTRY list, LARGE_INTEGER previousKey, LARGE_INTEGER newKey);
HANDLE removeFile(PLIST_ENTRY list, LARGE_INTEGER key);

#endif //FILE_LIST_H





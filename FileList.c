/*++
Source file for the file list structure for tracking active files
Author: Conor McLaughlin
Date: May 26, 2017
--*/
#include "FileList.h"

/*
Function to add a snapshot to the end of the list

Arguments:

listHead - pointer to the list to be added to

key - the file index number of the file we have taken a snapshot of

file - a pointer to the associated snapshot
*/
void addFile(PLIST_ENTRY listHead, LARGE_INTEGER key, HANDLE file) {
	
	PSnapshot newSnapshot = ExAllocatePoolWithTag(PagedPool, sizeof(snapshot), 'List');
	newSnapshot->file = file;
	newSnapshot->key.HighPart = key.HighPart;
	newSnapshot->key.LowPart = key.LowPart;
	newSnapshot->key.QuadPart = key.QuadPart;
	InsertTailList(listHead, &(newSnapshot->listEntry));
	
}

/*
Function to return a pointer to the snapshot associated with the given key

Arguments:

listHead - pointer to list to retrieve a file from

key - the file index number to search our list for

Return Value:

A pointer to the snapshot associated with the given key, or NULL if no such key is found
*/
HANDLE getFile(PLIST_ENTRY listHead, LARGE_INTEGER key) {
	PLIST_ENTRY current = listHead->Flink;

	// iterate over the list, stop when match found or we're out of entries
	while (current != listHead) {
		PSnapshot currentSnapshot = (PSnapshot) CONTAINING_RECORD(current, snapshot, listEntry);
		if (key.QuadPart == currentSnapshot->key.QuadPart) {
			return currentSnapshot->file;
		}
		else {
			current = current->Flink;
		}
	}

	// reached end of list, no file. Return a null handle
	return NULL;
}

/*
Function to change the key value associated with a particular snapshot

Arguments:

listHead - pointer to list to update

previousKey - the current key of the snapshot whose key we want to update

newKey - the new key value for the desired snapshot
*/
void updateKey(PLIST_ENTRY listHead, LARGE_INTEGER previousKey, LARGE_INTEGER newKey) {
	PLIST_ENTRY current = listHead->Flink;

	while (current != listHead) {
		PSnapshot currentSnapshot = (PSnapshot)CONTAINING_RECORD(current, snapshot, listEntry);
		if (previousKey.QuadPart == currentSnapshot->key.QuadPart) {
			currentSnapshot->key = newKey;
		}
	}
}

/*
Function to remove the snapshot associated with the given key

Arguments:

listHead - pointer to the list to remove from

key - the file index number associated with the snapshot we want to remove

Return Value:

The HANDLE of the snapshot that was removed from the list, or NULL.
*/
HANDLE removeFile(PLIST_ENTRY listHead, LARGE_INTEGER key) {
	PLIST_ENTRY current = listHead->Flink;

	while (current != listHead) {
		PSnapshot currentSnapshot = (PSnapshot)CONTAINING_RECORD(current, snapshot, listEntry);
		if (key.QuadPart == currentSnapshot->key.QuadPart) {
			RemoveEntryList(current);
			HANDLE retHandle = currentSnapshot->file;
			ExFreePoolWithTag(currentSnapshot, 'List');
			return retHandle;
		}
		else {
			current = current->Flink;
		}
	}

	return NULL;
}


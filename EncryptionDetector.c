/*++
Source file for logic to attempt to determine whether files are encrypted
Author: Conor McLaughlin
Date: June 7, 2017
--*/

#include "EncryptionDetector.h"

BOOLEAN isEncrypted(PFILE_OBJECT file, PFLT_INSTANCE instance, ULONG sectorSize) {

	LARGE_INTEGER readOffset = { 0 };
	ULONG totalBytesRead = 0;

	ULONG nonRandomBlockCount = 0;
	const USHORT nonRandomBlockThreshold = 100;
	const unsigned int chiSquareNonRandomThreshold = 512;
	
	int entropyInt = 0;

	// allocate and initialize array of byte counts for entropy calculation
	ULONG * byteCounts = ExAllocatePoolWithTag(PagedPool, sizeof(ULONG) * 256, 'byte');
	for (unsigned int i = 0; i < 256; i++) {
		byteCounts[i] = 0;
	}

	// allocate array of byte counts for chi-square calculations
	USHORT * occurrences = ExAllocatePoolWithTag(PagedPool, sizeof(USHORT) * 256, 'chi');

	// allocate file read buffer
	PVOID buffer = ExAllocatePoolWithTag(PagedPool, sectorSize, 'buff');

	
	NTSTATUS status;

	// read file and count byte occurrences
	while (TRUE) {

		if (buffer != NULL && byteCounts != NULL) {

			ULONG bytesRead;

			// attempt to read file
			status = FltReadFile(instance, file, &readOffset, sectorSize, buffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &bytesRead, NULL, NULL);

			// unsuccessful read -> check for expected error, otherwise conservatively return unencrypted
			if (!NT_SUCCESS(status)) {
				if (status == STATUS_END_OF_FILE) {
					break;
				}
				else {
					return FALSE;
				}
			}
			// successful read -> count byte occurrences and perform chi-square statistic calculations per 32 bytes
			else {
				totalBytesRead += bytesRead;
				unsigned char* bytes = (unsigned char*) buffer;

				// save floating point state
				KFLOATING_SAVE chiSquareSave;
				status = KeSaveFloatingPointState(&chiSquareSave);

				// expected occurrences per byte given a 32-byte block and a perfectly uniform byte distribution
				float expectedOccurrences = 0.125;
				// variable to measure degree to which byte counts deviate from a random distribution
				float chiSquareStatistic = 0;
				
				for (unsigned int i = 0; i < bytesRead; i++) {
					
					// increment overall byte counts for later entropy calculation
					unsigned char byte = bytes[i];
					byteCounts[byte]++;

					// if this is a non-zero multiple of 32, time to calculate chi-square statistics
					if (i % 32 == 0) {
						
						// check non-zero
						if (i > 0) {

							//perform chi-square calculations for each of the 256 possible bytes
							for(unsigned int j = 0; j < 256; j++) {
								USHORT byteOccurrences = occurrences[j];
								occurrences[j] = 0;
								chiSquareStatistic += ((byteOccurrences - expectedOccurrences) * (byteOccurrences - expectedOccurrences) / expectedOccurrences);
							}
							// check if sum exceeds the threshold
							if (chiSquareStatistic >= chiSquareNonRandomThreshold) {
								nonRandomBlockCount++;
							}
							chiSquareStatistic = 0;
						}
						else {
							// zero out occurrence count
							for (unsigned int k = 0; k < 256; k++) {
								occurrences[k] = 0;
							}
						}
					}
					// increment byte counts for chi-square statistics
					occurrences[byte]++;
				}

				KeRestoreFloatingPointState(&chiSquareSave);
			}

			// extra error check
			if (bytesRead < sectorSize) {
				break;
			}

			// update byte offset for file read
			readOffset.QuadPart += bytesRead;
			
		}
		else {
			break;
		}
	}

	// free read buffer
	if (buffer != NULL) {
		ExFreePoolWithTag(buffer, 'buff');
	}

	// free chi-square byte count buffer
	if (occurrences != NULL) {
		ExFreePoolWithTag(occurrences, 'chi');
	}

	KFLOATING_SAVE save;
	status = KeSaveFloatingPointState(&save);

	// if successful read and bytes read
	if (NT_SUCCESS(status) && totalBytesRead != 0) {
		// bytes are counted -> calculate overall entropy
		double entropy = 0;
		for (int i = 0; i < 256; i++) {
			float p = byteCounts[i] / (float) totalBytesRead;
			if (p > 0) {
				entropy -= (p * (log(p) / log(256)));
			}
		}

		// convert entropy to int value to use outside of floating point safe guards
		entropyInt = (int)(1000 * entropy);
	}

	KeRestoreFloatingPointState(&save);

	// free byte count 
	if (byteCounts != NULL) {
		ExFreePoolWithTag(byteCounts, 'byte');
	}

	// Requirements to be deemed encrypted:
	// File has high entropy
	// File's chi-square fit differs substantially from a perfectly random distribution
	// Enough bytes have been read to get a meaningful sense of the contents of the file
	// (Tiny files can cause false positives, and are unlikely to be valuable to any users)
	return (totalBytesRead >= 512 && entropyInt >= 900 && nonRandomBlockCount <= nonRandomBlockThreshold);
}

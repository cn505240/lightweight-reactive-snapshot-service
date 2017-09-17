/*++
Header file for logic to determine whether a file is encrypted or not
Author: Conor McLaughlin
Date: June 7, 2017
--*/
#include <fltKernel.h>

#ifndef ENCRYPTION_DETECTOR_H
#define ENCRYPTION_DETECTOR_H

BOOLEAN isEncrypted(PFILE_OBJECT file, PFLT_INSTANCE instance, ULONG sectorSize);

#endif // !ENCRYPTION_DETECTOR_H


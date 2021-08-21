#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)//2 6:30
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_DATA)//2 7:30

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "ntddk.h"
#include <stdio.h>

int count_list = 0;

struct ListFile
{
	WCHAR file_name[200];
	WCHAR proccess_name[100];
	int Mask;
} List[50];

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\device555");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\symlinkdevice555");
PDEVICE_OBJECT DeviceObject = NULL;

PFLT_FILTER FilterHandle = NULL;

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);


NTSTATUS
GetProcessImageName(
	PEPROCESS eProcess,
	PUNICODE_STRING* ProcessImageName
);

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);
QUERY_INFO_PROCESS ZwQueryInformationProcess;


const FLT_OPERATION_REGISTRATION Callbacks[] = {
	{IRP_MJ_CREATE,0,MiniPreCreate,MiniPostCreate},
	{IRP_MJ_READ,0,MiniPreRead,NULL},
	{IRP_MJ_WRITE,0,MiniPreWrite,NULL},
	{IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),//size of structure
	FLT_REGISTRATION_VERSION,//version
	0,//flags
	NULL,//context regixtration member
	Callbacks,//we register callbacks
	MiniUnload,//we register unload function
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};


NTSTATUS
FileOpen()
/*
	Function to open a config file.
*/
{
	NTSTATUS status;
	UNICODE_STRING    fullFileName;
	HANDLE            fileHandle;
	IO_STATUS_BLOCK   iostatus;
	OBJECT_ATTRIBUTES oa;
	LARGE_INTEGER byteOffset;
	CHAR buffer_data[10000];
	memset(buffer_data, 0, 10000);

	KdPrint(("Start read file\n"));

	RtlInitUnicodeString(&fullFileName,
		L"\\??\\C:\\Users\\User\\Documents\\config.sql");

	InitializeObjectAttributes(&oa,
		&fullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(&fileHandle,
		GENERIC_READ,
		&oa,
		&iostatus,
		0,  // alloc size = none
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (status != STATUS_SUCCESS)
	{
		KdPrint(("Oops.. File 'config.sql' not find.\n"));
		ZwClose(fileHandle);
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		DbgPrint("File 'config.sql' success open.\n");
		byteOffset.LowPart = 0;
		byteOffset.HighPart = 0;
		status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iostatus, buffer_data, 10000, &byteOffset, NULL);
		int offset = strlen("CREATE TABLE config (\n\r\tFile TEXT(100),\n\r\tProcess TEXT(100),\n\r\tMask INT\n\r);");

		while (buffer_data[offset] != 0)
		{
			offset += strlen("INSERT INTO config VALUES (\'");
			int i = 0;
			char name_temp[50] = { 0 };
			while (buffer_data[i + offset] != '\'')
			{
				List[count_list].file_name[i] = (WCHAR)buffer_data[i + offset];
				i++;
			}
			List[count_list].file_name[i] = '\0';

			offset += i + strlen(", \'") + 1;
			i = 0;
			while (buffer_data[i + offset] != '\'')
			{
				List[count_list].proccess_name[i] = (WCHAR)buffer_data[i + offset];
				i++;
			}
			List[count_list].proccess_name[i] = '\0';

			offset += i + strlen(", ") + 1;
			List[count_list].Mask = buffer_data[offset] - '0';

			KdPrint(("Right ¹%d: file: %ws, SID: %ws, mask: %d\n", count_list + 1, List[count_list].file_name, List[count_list].proccess_name, List[count_list].Mask));
			offset += strlen(");\n\r") + 1;

			count_list++;
		}
		ZwClose(fileHandle);
		return status;
	}
}

WCHAR* 
GetUser()
{
	TOKEN_USER* user = NULL;
	HANDLE token = NULL;
	NTSTATUS status;
	unsigned long len;
	//DbgPrint("Searching for user\r\n"); 

	if ((status = ZwOpenThreadTokenEx(NtCurrentThread(), TOKEN_READ, TRUE, OBJ_KERNEL_HANDLE, &token)) != STATUS_SUCCESS)
	{
		status = ZwOpenProcessTokenEx(NtCurrentProcess(), TOKEN_READ, OBJ_KERNEL_HANDLE, &token);
	}

	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	status = ZwQueryInformationToken(token, TokenUser, NULL, 0, &len);
	{
		if ((user = ExAllocatePoolWithTag(NonPagedPool, len, 'hp1t')))
		{
			if ((status = ZwQueryInformationToken(token, TokenUser, user, len, &len)) == STATUS_SUCCESS)
			{
				if (user->User.Sid != NULL)
				{

					UNICODE_STRING NameBuffer;
					NameBuffer.Buffer = NULL;
					if (NT_SUCCESS(RtlConvertSidToUnicodeString(&NameBuffer, user->User.Sid, TRUE)))
						return NameBuffer.Buffer;
					if (NameBuffer.Buffer != NULL)
						ExFreePool(NameBuffer.Buffer);
				}
			}
			ExFreePoolWithTag(user, 'hp1t');
		}
	}
	return NULL;
	ZwClose(token);
}

NTSTATUS
GetProcessImageName(
	PEPROCESS eProcess,
	PUNICODE_STRING* ProcessImageName
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG returnedLength;
	HANDLE hProcess = NULL;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process 

	if (eProcess == NULL)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	status = ObOpenObjectByPointer(eProcess,
		0, NULL, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		return status;
	}

	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (ZwQueryInformationProcess == NULL)
		{
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			status = STATUS_UNSUCCESSFUL;
			goto cleanUp;
		}
	}

	/* Query the actual size of the process path */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer 
		0, // buffer size 
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		DbgPrint("ZwQueryInformationProcess status = %x\n", status);
		goto cleanUp;
	}

	*ProcessImageName = ExAllocatePoolWithTag(NonPagedPoolNx, returnedLength, '2gat');

	if (ProcessImageName == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanUp;
	}
	/* Retrieve the process path from the handle to the process */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		*ProcessImageName,
		returnedLength,
		&returnedLength);

	if (!NT_SUCCESS(status)) ExFreePoolWithTag(*ProcessImageName, '2gat');

cleanUp:

	ZwClose(hProcess);
	return status;
}

void NotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	NTSTATUS status;
	ULONG returnedLength;
	UNICODE_STRING    fullFileName;
	HANDLE            fileHandle;
	IO_STATUS_BLOCK   iostatus;
	OBJECT_ATTRIBUTES oa;

	LARGE_INTEGER time, local_time;
	TIME_FIELDS tf;
	KeQuerySystemTime(&time);
	ExSystemTimeToLocalTime(&time, &local_time);
	RtlTimeToTimeFields(&local_time, &tf);

	WCHAR buf_time[10] = { 0 }, temp_buf[3] = { 0 };

	buf_time[1]= tf.Hour % 10 + '0';
	if (tf.Hour < 10)
		buf_time[0] = '0';
	else
	{
		tf.Hour /= 10;
		buf_time[0] = tf.Hour + '0';
	}
	buf_time[2] = ':';

	buf_time[4] = tf.Minute % 10 + '0';
	if (tf.Minute < 10)
		buf_time[3] = '0';
	else
	{
		tf.Minute /= 10;
		buf_time[3] = tf.Minute + '0';
	}
	buf_time[5] = ':';

	buf_time[7] = tf.Second % 10 + '0';
	if (tf.Second < 10)
		buf_time[6] = '0';
	else
	{
		tf.Second /= 10;
		buf_time[6] = tf.Second + '0';
	}
	buf_time[8] = ' ';


	int  prc_pid = PtrToInt(ProcessId), length = 0, tmp;
	WCHAR buf_prc_pid[10] = { 0 };
	tmp = prc_pid;
	for (; tmp; tmp /= 10, length++);
	for (int i = 0; i < length; i++)
	{
		buf_prc_pid[length - 1 - i] = prc_pid % (10) + 48;
		prc_pid /= 10;
	}


	WCHAR buffer[500] = { 0 };
	PEPROCESS pProcess = NULL;
	PUNICODE_STRING processName = NULL;
	status = PsLookupProcessByProcessId(ProcessId, &pProcess);
	GetProcessImageName(pProcess, &processName);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	RtlInitUnicodeString(&fullFileName,
		L"\\??\\C:\\Users\\User\\Documents\\notif.txt");

	InitializeObjectAttributes(&oa,
		&fullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(&fileHandle,
		FILE_APPEND_DATA,
		&oa,
		&iostatus,
		0,  
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (status != STATUS_SUCCESS)
	{
		KdPrint(("Oops.. File 'notif.txt' not find.\n"));
		ZwClose(fileHandle);
		return;
	}
	else
	{
		WCHAR* start = L" process created: ";
		WCHAR* stop = L" process deleted: ";
		WCHAR* proc = L" process ";
		WCHAR* pid = L", PID ";
		WCHAR* step = L"\n";
		RtlCopyMemory(buffer, processName->Buffer, processName->MaximumLength);
		int i = 0;
		for (; i < 500; i++)
			if (buffer[i] == '\0')
				break;

		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, buf_time, 8 * 2, NULL, NULL);
		if (Create == TRUE) //created
			status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, start, 17 * 2, NULL, NULL);
		else				//deleted
			status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, stop, 17 * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, proc, 9 * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, buffer, i * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, pid, 5 * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, buf_prc_pid, length * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, step, 1 * 2, NULL, NULL);
		ZwClose(fileHandle);
	}
}


NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	KdPrint(("Driver unloaded successfully\r\n"));
	FltUnregisterFilter(FilterHandle);
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	PsSetCreateProcessNotifyRoutine(NotifyRoutine, TRUE);
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(DeviceObject);
	KdPrint(("Driver unloaded successfully\r\n"));
}


FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PVOID* CompletionContext)
{
	NTSTATUS status;

	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	WCHAR NameBuf[512];
	memset(NameBuf, 0, 512);

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status))
	{
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status))
		{
			if (FileNameInfo->Name.MaximumLength < 512)
			{
				RtlCopyMemory(NameBuf, FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);
				if (wcsstr(NameBuf, L"config.sql"))
				{
					WCHAR buffer[512] = { 0 };
					PUNICODE_STRING processName = NULL;
					GetProcessImageName(PsGetCurrentProcess(), &processName);
					RtlCopyMemory(buffer, processName->Buffer, processName->MaximumLength);
					if (wcsstr(buffer, L"user_app.exe") == NULL)
					{
						DbgPrint("access denied (CREATE config file)\n\n");
						Data->IoStatus.Status = STATUS_ACCESS_DENIED;
						Data->IoStatus.Information = 0;
						FltReleaseFileNameInformation(FileNameInfo);
						return FLT_PREOP_COMPLETE;
					}
				}
				for (int i = 0; i < count_list; i++)
				{
					if (wcsstr(NameBuf, List[i].file_name + 3))
					{
						WCHAR* User = GetUser();
						if (wcsstr(User, List[i].proccess_name))
						{
							if ((List[i].Mask & 4) == 0)
							{
								KdPrint(("access denied (CREATE)\n\n"));
								Data->IoStatus.Status = STATUS_ACCESS_DENIED;
								Data->IoStatus.Information = 0;
								FltReleaseFileNameInformation(FileNameInfo);
								return FLT_PREOP_COMPLETE;
							}
						}
					}
				}
			}
		}

		FltReleaseFileNameInformation(FileNameInfo);
	}
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	NTSTATUS status;

	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	PUNICODE_STRING ProcessName = NULL;
	WCHAR NameBuf[512];
	memset(NameBuf, 0, 512);

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status))
	{
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status))
		{
			if (FileNameInfo->Name.MaximumLength < 512)
			{
				RtlCopyMemory(NameBuf, FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);
				for (int i = 0; i < count_list; i++)
				{
					if (wcsstr(NameBuf, List[i].file_name + 3))
					{
						WCHAR* User = GetUser();
						if (wcsstr(User, List[i].proccess_name))
						{
							if ((List[i].Mask & 2) == 0)
							{
								KdPrint(("access denied (READ)\n\n"));
								Data->IoStatus.Status = STATUS_ACCESS_DENIED;
								Data->IoStatus.Information = 0;
								FltReleaseFileNameInformation(FileNameInfo);
								return FLT_PREOP_COMPLETE;
							}
						}
					}
				}
			}
		}

		FltReleaseFileNameInformation(FileNameInfo);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	PUNICODE_STRING ProcessName = NULL;
	WCHAR NameBuf[512];
	memset(NameBuf, 0, 512);

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status))
	{
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status))
		{
			if (FileNameInfo->Name.MaximumLength < 512)
			{
				RtlCopyMemory(NameBuf, FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);
				for (int i = 0; i < count_list; i++)
				{
					if (wcsstr(NameBuf, List[i].file_name + 3))
					{
						WCHAR* User = GetUser();
						if (wcsstr(User, List[i].proccess_name))
						{
							if ((List[i].Mask & 1) == 0)
							{
								KdPrint(("access denied (WRITE)\n\n"));
								Data->IoStatus.Status = STATUS_ACCESS_DENIED;
								Data->IoStatus.Information = 0;
								FltReleaseFileNameInformation(FileNameInfo);
								return FLT_PREOP_COMPLETE;
							}
						}
					}
				}
			}
		}

		FltReleaseFileNameInformation(FileNameInfo);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



NTSTATUS DispatchPassThru(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (irpsp->MajorFunction)
	{
	case IRP_MJ_CREATE:
	{
		DbgPrint(("create request\r\n"));
		break;
	}
	case IRP_MJ_CLOSE:
	{
		DbgPrint(("close request\r\n"));
		break;
	}
	default:
	{
		status = STATUS_INVALID_PARAMETER;
		DbgPrint(("other request\r\n"));
		break;
	}
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DispatchDevCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG inlength = irpsp->Parameters.DeviceIoControl.InputBufferLength;//buffer len in sending function
	ULONG outlength = irpsp->Parameters.DeviceIoControl.OutputBufferLength;//buffer len in receiving function
	ULONG returnlength = 0;

	WCHAR* demo = L"command success send\n";

	switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
	{
	case DEVICE_SEND:
	{
		DbgPrint("New command received: %ws\r\n", buffer);
		if (wcscmp(buffer, L"update") == 0)
		{
			count_list = 0;
			FileOpen();
		}
		else if (wcscmp(buffer, L"on") == 0)
		{
			KdPrint(("PsSetCreateProcessNotifyRoutine ON\n"));
			PsSetCreateProcessNotifyRoutine(NotifyRoutine, FALSE);
		}
		else if (wcscmp(buffer, L"off") == 0)
		{
			KdPrint(("PsSetCreateProcessNotifyRoutine OFF\n"));
			PsSetCreateProcessNotifyRoutine(NotifyRoutine, TRUE);
		}
		returnlength = (wcsnlen(buffer, 511) + 1) * 2;
		break;
	}
	case DEVICE_REC:
	{
		wcsncpy(buffer, demo, 511);
		KdPrint(("send data is %ws\r\n", demo));
		returnlength = (wcsnlen(buffer, 511) + 1) * 2;
		break;
	}
	default:
	{
		status = STATUS_INVALID_PARAMETER;
		break;
	}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = returnlength;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	DriverObject->DriverUnload = Unload;

	//creating device
	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		//create device failed
		KdPrint(("creating device failed\r\n"));
		return status;
	}

	status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("creating sym link failed\r\n"));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DispatchPassThru;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDevCTL;
	
	FileOpen();
	KdPrint(("Driver loaded successfully\r\n"));

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(FilterHandle);
	
		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter(FilterHandle);
		}

	}

	return status;
}

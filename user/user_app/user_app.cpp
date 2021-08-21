#include <iostream>
#include <windows.h>
#include <winioctl.h>
#include <fstream>
#include <string>
#include <vector>
#include <sddl.h>

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)//2 22:30
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_DATA)//2 23:00

HANDLE devicehandle = NULL;

int count_list = 0;

struct ListFile
{
    char file_name[200];
    char sid[100];
    int Mask;
} List[50];

char* get_sid(const char* Owner)
{
    PSID Sid = nullptr;
    if (!ConvertStringSidToSidA(Owner, &Sid))
    {
        SID_NAME_USE Use;
        DWORD cSid = 0, ReferencedDomain = 0;
        int res = LookupAccountNameA(nullptr, Owner, nullptr, &cSid, nullptr, &ReferencedDomain, &Use);
        if (cSid)
        {
            Sid = LocalAlloc(LMEM_FIXED, cSid);
            if (Sid)
            {
                char* ReferencedDomainName = new char[ReferencedDomain];
                if (ReferencedDomainName)
                {
                    if (!LookupAccountNameA(nullptr, Owner, Sid, &cSid, ReferencedDomainName, &ReferencedDomain, &Use))
                    {
                        return NULL;
                    }
                    char* StringSid = NULL;
                    ConvertSidToStringSidA(Sid, &StringSid);
                    return StringSid;
                }
            }
        }
    }
}

void write_file()
{
    std::ofstream file_conf;
    file_conf.open("C:\\Users\\User\\Documents\\config.sql");
    //file_conf.open("config.sql");
    file_conf << "CREATE TABLE config (\n\tFile TEXT(100),\n\tSID TEXT(100),\n\tMask INT\n);\n\n";
    for (int i = 0; i < count_list; i++)
    {
        file_conf << "INSERT INTO config VALUES (\'";
        file_conf << List[i].file_name;
        file_conf << "\', \'";
        file_conf << List[i].sid;
        file_conf << "\', ";
        file_conf << List[i].Mask;
        file_conf << ");\n";
    }
    file_conf.close();
}

bool parse_file()
{
    std::ifstream file_conf("C:\\Users\\User\\Documents\\config.sql", std::ios::in | std::ios::binary);
    //std::ifstream file_conf("config.sql", std::ios::in | std::ios::binary);
    char buffer_data[10000];
    const char ch = '\0';
    memset(buffer_data, 0, 10000);

    if (!file_conf)
    {
        printf("Oops.. File 'config.sql' not find.\n");
        return 0;
    }
    else
    {
        file_conf.getline(buffer_data, 10000, ch);
        int offset = strlen("CREATE TABLE config (\n\r\tFile TEXT(100),\n\r\tProcess TEXT(100),\n\r\tMask INT\n\r);");
        //printf("%s\n", buffer_data+offset);
        while (buffer_data[offset] != NULL)
        {
            offset += strlen("INSERT INTO config VALUES (\'");
            int i = 0;
            char name_temp[200] = { 0 };
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
                List[count_list].sid[i] = (WCHAR)buffer_data[i + offset];
                i++;
            }
            List[count_list].sid[i] = '\0';

            offset += i + strlen(", ") + 1;
            List[count_list].Mask = buffer_data[offset] - '0';
            offset += strlen(");\n\r") + 1;
            //printf("%s\n", List[count_list].file_name);
            count_list++;
        }
        file_conf.close();
        return 1;
    }
}

int find_rigth(char name[200], char sid[100])
{
    for (int i = 0; i < count_list; i++)
        if (!strncmp(name, List[i].file_name, strlen(List[i].file_name)))
            if (!strncmp(sid, List[i].sid, strlen(List[i].sid)))
                return i+1;
    return 0;
}

void show()
{
    for (int i = 0; i < count_list; i++)
        printf("Right number %d: file: %s, sid: %s, mask: %d\n", i + 1, List[i].file_name, List[i].sid, List[i].Mask);
}

void new_rigth()
{
    char name_user[200] = { 0 }, file[200] = { 0 }, rigth_str[100] = { 0 };
    char* sid = NULL;
    int rigth = 0;
    printf("enter name object: ");
    fgets(name_user, 100, stdin);
    name_user[strlen(name_user) - 1] = 0;
    //printf("%s*\n", name_user);
    sid = get_sid(name_user);
    if (sid == NULL)
    {
        printf("no such subject in system\n");
        return;
    }

    printf("enter file name: ");
    fgets(file, 200, stdin);
    file[strlen(file) - 1] = 0;

    printf("enable rigth 'WRITE'? [y,n] ");
    fgets(rigth_str, 100, stdin);
    rigth_str[strlen(rigth_str) - 1] = 0;
    if (!strncmp("y", rigth_str, 1))
        rigth = rigth | 1;

    printf("enable rigth 'READ'? [y,n] ");
    fgets(rigth_str, 100, stdin);
    rigth_str[strlen(rigth_str) - 1] = 0;
    if (!strncmp("y", rigth_str, 1))
        rigth = rigth | 2;

    printf("enable rigth 'CREATE'? [y,n] ");
    fgets(rigth_str, 100, stdin);
    rigth_str[strlen(rigth_str) - 1] = 0;
    if (!strncmp("y", rigth_str, 1))
        rigth = rigth | 4;

    if (!find_rigth(file, sid))
    {
        memcpy(List[count_list].file_name, file, strlen(file));
        List[count_list].file_name[strlen(file)] = '\0';
        memcpy(List[count_list].sid, sid, strlen(sid));
        List[count_list].sid[strlen(sid)] = '\0';
        List[count_list].Mask = rigth;
        count_list++;
    }
    else
        List[find_rigth(file, sid)-1].Mask = rigth;
}

void delete_rigth()
{
    int number_rigth = 0;
    char number_r[10] = { 0 };
    printf("enter number rigth: ");
    fgets(number_r, 100, stdin);
    number_r[strlen(number_r) - 1] = 0;
    number_rigth = atoi(number_r);
    number_rigth--;
    if (number_rigth >= 0 && number_rigth < count_list)
    {
        memcpy(List[number_rigth].file_name, List[count_list - 1].file_name, strlen(List[count_list - 1].file_name));
        List[number_rigth].file_name[strlen(List[count_list - 1].file_name)] = '\0';
        memcpy(List[number_rigth].sid, List[count_list - 1].sid, strlen(List[count_list - 1].sid));
        List[number_rigth].sid[strlen(List[count_list - 1].sid)] = '\0';
        List[number_rigth].Mask = List[count_list - 1].Mask;
        count_list--;
    }
}


int main(void)
{
	//open device
	devicehandle = CreateFile(L"\\\\.\\symlinkdevice555", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (devicehandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "not valid value" << std::endl;
		system("pause");
		return 0;
	}
	std::cout << "valid value" << std::endl;
    setlocale(LC_ALL, "russian");
    system("chcp 1251");
    printf("Choose command:\n\
        show\t\t-\tshow all rigth\n\
        new_r\t\t-\tcreate new rigth\n\
        del_r\t\t-\tdelete rigth\n\
        update_r\t-\tupdate driver\'s informarion\n\
        enable_n\t-\tenable notification\n\
        disable_n\t-\tdisable notification\n\
        exit\t\t-\texit programm\n");
    char command[2048] = { 0 };
    parse_file();
    while (1)
    {
        fflush(stdin);
        printf("# ");
        fgets(command, 2048, stdin);
        command[strlen(command) - 1] = 0;
        if (!strncmp(command, "show", strlen("show")))
        {
            show();
        }
        else if (!strncmp(command, "new_r", strlen("new_r")))
        {
            new_rigth();
            write_file();
        }
        else if (!strncmp(command, "del_r", strlen("del_r")))
        {
            delete_rigth();
            write_file();
        }
        else if (!strncmp(command, "update_r", strlen("update_r")))
        {
            WCHAR message[] = L"update";
            ULONG returnlength = 0;
            if (devicehandle != INVALID_HANDLE_VALUE && devicehandle != NULL)
            {
                if (!DeviceIoControl(devicehandle, DEVICE_SEND, message, (wcslen(message) + 1) * 2, NULL, 0, &returnlength, 0))
                    std::cout << "send error" << std::endl;
                else
                    std::cout << "send " << returnlength << " bytes " << std::endl;
            }
        }
        else if (!strncmp(command, "enable_n", strlen("enable_n")))
        {
            WCHAR message[] = L"on";
            ULONG returnlength = 0;
            if (devicehandle != INVALID_HANDLE_VALUE && devicehandle != NULL)
            {
                if (!DeviceIoControl(devicehandle, DEVICE_SEND, message, (wcslen(message) + 1) * 2, NULL, 0, &returnlength, 0))
                    std::cout << "send error" << std::endl;
                else
                    std::cout << "send " << returnlength << " bytes " << std::endl;
            }
        }
        else if (!strncmp(command, "disable_n", strlen("disable_n")))
        {
            WCHAR message[] = L"off";
            ULONG returnlength = 0;
            if (devicehandle != INVALID_HANDLE_VALUE && devicehandle != NULL)
            {
                if (!DeviceIoControl(devicehandle, DEVICE_SEND, message, (wcslen(message) + 1) * 2, NULL, 0, &returnlength, 0))
                    std::cout << "send error" << std::endl;
                else
                    std::cout << "send " << returnlength << " bytes " << std::endl;
            }
        }
        else if (!strncmp(command, "exit", strlen("exit")))
        {
            CloseHandle(devicehandle);
            return 0;
        }
        else
            std::cout << "error command" << std::endl;
    }

	return 0;
}
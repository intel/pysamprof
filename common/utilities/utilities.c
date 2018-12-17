#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <aclapi.h>
#endif

#include "../logging/logging.h"
#include "../sal_common.h"
#include "utilities.h"

#ifdef _WIN32
const char* s_delimiter = "\\";
#else
const char* s_delimiter = "/";
#endif

#ifdef _WIN32
static operation_result_t create_dir(const char* path)
{
    pysamprof_security_attrs_t sattrs;
    operation_result_t status;
    status = create_tight_security_attrs(&sattrs);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_ERROR, "Cannot create security attributes for %s directory: %s", path, get_operation_result_str(status));
        return status;
    }
    if (!CreateDirectory(path, &(sattrs.attrs)))
    {
        PYSAMPROF_LOG(PL_ERROR, "Failed to create directory '%s', error: %ld", path, GetLastError());
        status = free_security_attrs(&sattrs);
		if (status != or_okay)
		{
			PYSAMPROF_LOG(PL_WARNING, "Cannot free security attributes for %s directory: %s", path, get_operation_result_str(status));
		}
        return or_fail;
    }
    status = free_security_attrs(&sattrs);
    if (status != or_okay)
    {
        PYSAMPROF_LOG(PL_WARNING, "Cannot free security attributes for %s directory: %s", path, get_operation_result_str(status));
    }
    return or_okay;
}
void msleep(int msec)
{
    Sleep(msec);
}
static void normalize_path(char *dir)
{
    char *s;
    // normalize path on Windows: replace '/' slashes with '\'
    for(s = dir; *s != '\0'; s++)
    {
        if (*s == '/') *s = '\\';
    }
}
#elif defined(__linux__)
static operation_result_t create_dir(const char* path)
{
    if (mkdir(path, S_IRWXU) != 0)
    {
        PYSAMPROF_LOG(PL_ERROR, "Failed to create directory '%s', error: %d", path, errno);
        return or_fail;
    }
    return or_okay;
}
void msleep(int msec)
{
    struct timespec timeout;
    timeout.tv_sec = msec / 1000;
    timeout.tv_nsec = (msec % 1000) * 1000000L;
    nanosleep(&timeout, NULL);
}
#else
#error Unsupported platform
#endif

static int check_two_dots(const char *dir)
{
    // check that there's no ".." in the string
    int dot_found = 0;
    const char* ch;
    for (ch = dir; *ch != '\0'; ch++)
    {
        if (*ch == '.')
        {
            dot_found++;
            if (dot_found >= 2)
            {
                return 1;
            }
        }
        else
        {
            dot_found = 0;
        }
    }
    return 0;
}

operation_result_t mkdir_recoursive(const char *dir)
{
    sal_file_attrs_t file_attrs;
    char *str, *dir_copy, *s, *rest_s, *created_dir;
    size_t bufsize, offset;

    if (dir == NULL) return or_fail;

    if (check_two_dots(dir)) {
        PYSAMPROF_LOG(PL_ERROR, "mkdir_recoursive does not accept paths with '..' inside, got '%s'", dir);
        return or_cannot_open_file;
    }

    dir_copy = sal_strdup(dir);
    if (dir_copy == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: failed to copy string during recursive mkdir");
        return or_fail;
    }

    sal_normalize_path_win(dir_copy);
    
    s = dir_copy;
    rest_s = dir_copy;
    
    bufsize = strlen(s) + 1 /* for NULL */ + 1 /* for final slash */;
    created_dir = (char *) malloc(bufsize);
    if (created_dir == NULL)
    {
        PYSAMPROF_LOG(PL_ERROR, "Not enough memory: failed to allocate string during recursive mkdir");
        free(dir_copy);
        return or_insufficient_memory;
    }
    offset = 0;
    while(dir_copy[offset] != '\0' && dir_copy[offset] == *s_delimiter)
    {
        created_dir[offset] = dir_copy[offset];
        offset++;
    }
    created_dir[offset] = '\0';

    while (( str = sal_strtok_s(s, s_delimiter, &rest_s)) != NULL)
    {
        s = NULL;
        if (str != dir)
        {
            strcpy_s(created_dir + offset, bufsize - offset, str);
            offset += strlen(str);
            strcpy_s(created_dir + offset, bufsize - offset, s_delimiter);
            offset += strlen(s_delimiter);
        }

        if (sal_get_file_attributes(file_attrs, created_dir))
        {
            if (!sal_file_is_dir(file_attrs))
            {
                PYSAMPROF_LOG(PL_ERROR, "'%s' is not a directory", dir);
                free(created_dir);
                free(dir_copy);
                return or_fail;
            }
        }
        else
        {
            if (create_dir(created_dir) == or_fail)
            {
                free(created_dir);
                free(dir_copy);
                return or_fail;
            }
        }
        
    }
    free(dir_copy);
    free(created_dir);
    return or_okay;
}

#ifdef _WIN32
operation_result_t create_tight_security_attrs(pysamprof_security_attrs_t* result)
{
	PSECURITY_DESCRIPTOR sd;
	PACL acl = NULL;
	HANDLE token;
	PTOKEN_USER user_token;
	DWORD needed_size, size;
	PSID current_user = NULL, admins = NULL;
	EXPLICIT_ACCESS ea[2];
	SID_IDENTIFIER_AUTHORITY admin_sid = SECURITY_NT_AUTHORITY;

	if (result == NULL) return or_fail;
	result->acl = NULL;
	result->attrs.lpSecurityDescriptor = NULL;
	result->admin_sid = NULL;
	result->user_token = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get the token for current process, error: %u", GetLastError());
		return or_bad_permissions;
	}
	if (GetTokenInformation(token, TokenUser, NULL, 0, &needed_size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get the size for TokenUser structure, GetLastError() returned %u", GetLastError());
		CloseHandle(token);
		return or_fail;
	}
	user_token = (PTOKEN_USER)malloc(needed_size);
	if (user_token == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for TOKEN_USER structure");
		CloseHandle(token);
		return or_insufficient_memory;		
	}
	if (!GetTokenInformation(token, TokenUser, user_token, needed_size, &size))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot get user information from token, error: %u", GetLastError());
		CloseHandle(token);
		free(user_token);
		return or_bad_permissions;
	}
	current_user = user_token->User.Sid;

	CloseHandle(token);

	// Create a SID for the BUILTIN\Administrators group.
    if(!AllocateAndInitializeSid(&admin_sid, 2,
			SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
            &admins)) 
    {
		PYSAMPROF_LOG(PL_ERROR, "Cannot create admin SID, error: %u", GetLastError());
		free(user_token);
		return or_bad_permissions;
    }
	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

    ea[0].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | STANDARD_RIGHTS_ALL;
    ea[0].grfAccessMode = GRANT_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPTSTR)current_user;

	ea[1].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | STANDARD_RIGHTS_ALL;
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)admins;

	if (SetEntriesInAcl(2, ea, NULL, &acl) != ERROR_SUCCESS)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot set ACL entries, error: %u", GetLastError());
		if (admins) FreeSid(admins);
		free(user_token);
		return or_bad_permissions;
	}

	sd = (PSECURITY_DESCRIPTOR)(malloc(SECURITY_DESCRIPTOR_MIN_LENGTH));
	if (sd == NULL)
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot allocate memory for SECURITY_DESCRIPTOR");
		if (acl) LocalFree(acl);
		if (admins) FreeSid(admins);
		free(user_token);
		return or_insufficient_memory;
	}

	if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot initialize SECURITY_DESCRIPTOR, error: %u", GetLastError());
		free(sd);
		if (acl) LocalFree(acl);
		if (admins) FreeSid(admins);
		free(user_token);
		return or_cannot_make_security_descr;
	}
	if (!SetSecurityDescriptorOwner(sd, current_user, FALSE))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot set SECURITY_DESCRIPTOR owner, error: %u", GetLastError());
		free(sd);
		if (acl) LocalFree(acl);
		if (admins) FreeSid(admins);
		free(user_token);
		return or_cannot_make_security_descr;
	}

	if (!SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE))
	{
		PYSAMPROF_LOG(PL_ERROR, "Cannot set ACL in SECURITY_DESCRIPTOR, error: %u", GetLastError());
		free(sd);
		if (acl) LocalFree(acl);
		if (admins) FreeSid(admins);
		free(user_token);
		return or_cannot_make_security_descr;
	}

	result->attrs.nLength = sizeof(SECURITY_ATTRIBUTES);
	result->attrs.bInheritHandle = FALSE;
	result->attrs.lpSecurityDescriptor = sd;
	result->acl = acl;
	result->admin_sid = admins;
	result->user_token = user_token;
	return or_okay;
}

operation_result_t free_security_attrs(pysamprof_security_attrs_t* attrs)
{
	if (attrs == NULL) return or_fail;
	free(attrs->attrs.lpSecurityDescriptor);
	if (attrs->acl) LocalFree(attrs->acl);
	if (attrs->admin_sid) FreeSid(attrs->admin_sid);
	free(attrs->user_token);
	return or_okay;
}
#endif

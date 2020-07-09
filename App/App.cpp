/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

const int BUF_MAX_SIZE = 1000;
const int para_MAX_SIZE = 3;
const int para_MAX_LEN = 100; //same as max directory size

#define SPM_CREATE 0x65
#define SPM_CHANGE 0x66
#define SPM_DELETE 0x67

#define __NR_enc_rdafwr 333

void line_input(char in[BUF_MAX_SIZE]){
    char buf = 0;
    for(int i = 0; 1; i++){
        scanf("%c", &buf);
        in[i] = buf;
        if(buf == '\n'){
            in[i] = 0;
            break;
        }
        else if(i == BUF_MAX_SIZE && buf != '\n'){
            //buffer size error
            fprintf(stderr, "[error] MAX buffer size is %d\n", BUF_MAX_SIZE);
        }
    }
}

void parse_str(char in[BUF_MAX_SIZE], char out[para_MAX_SIZE][para_MAX_LEN]){
    char tmp[BUF_MAX_SIZE];
    int len = 0, para_size = 0, j = 0;
    //assume no space allows in first and last "in[]" components
    for(int i = 0; i < BUF_MAX_SIZE && in[i] != 0; i++){
        while(in[i] == ' ') i++;
        if(len != 0) tmp[len++] = ' ';
        while(in[i] != ' ' && in[i] != 0) {
            tmp[len++] = in[i];
            i++;
        }
    }
    
    for(int i = 0; i < len; i++){
        j = 0;
        while(tmp[i] != ' ' && i < len){
            out[para_size][j++] = tmp[i++];
        }
        out[para_size++][j] = 0;
    }
}

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;



/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

#define POLICY_LIST "/home/lass/jinhoon/policy_list"
char policy_arr[32][1000];
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
    printf("**************************************************************\n");
    printf("* SGX-SSD policy manager                                     *\n");
    printf("*                                                            *\n");
    printf("* press command and parameter                                *\n");
    printf("*                                                            *\n");
    printf("* ex) {create|change|delete} {ret_time} {Backup_cycle}       *\n");
    printf("*                                                            *\n");
    printf("* units:                                                     *\n");
    printf("* retention time : day                                       *\n");
    printf("* Backup cycle   : day                                       *\n");
    printf("**************************************************************\n");
    
    //assume aurora input
    char in[1000];
    line_input(in);
    //debug
    //printf("%s\n", in);
    
    char para_arr[para_MAX_SIZE][para_MAX_LEN]; //save parameters
    parse_str(in, para_arr);
    
    //debug
    
    printf("parameter lists : \n");
    for(int i = 0; i < para_MAX_SIZE; i++){
        printf("%s\n", para_arr[i]);
    }
    
    char path[100];
    int command, retention_time, backup_cycle, version_number, pid;
    
    int branch = 0;
    
    if(para_arr[0][0] == 'c' && para_arr[0][1] == 'r'){
        command = SPM_CREATE;
    }
    else if(para_arr[0][0] == 'c' && para_arr[0][1] == 'h'){
        command = SPM_CHANGE;
    }
    else if(para_arr[0][0] == 'd' || para_arr[0][0] == 'D'){
        command = SPM_DELETE;
    }
    else if(para_arr[0][0] == 'r' || para_arr[0][0] == 'R'){
        //no recovery
        command = 3;
        branch = 1;
    }
    else{
        fprintf(stderr, "error : command\n");
        return 0;
    }
    
    if(command == SPM_CHANGE){
        //what pid to change?
        printf("what pid to change : ");
        scanf("%d", &pid);
    }
    
    strcpy(path, para_arr[1]);
    
    if(!branch){
        //not recovery
        retention_time = atoi(para_arr[1]);
        backup_cycle = atoi(para_arr[2]);
        //version_number = atoi(para_arr[4]);
    }
    else{
        //recovery
        //??
    }
    //debug
    //printf("data : %d%s%d%d%d\n", command, path, retention_time, backup_cycle, version_number);
    printf("data : %d%d%d\n", command, retention_time, backup_cycle);
    
    FILE*fp = fopen(POLICY_LIST, "r+");
    
    int policy_cnt = 0;
    
    while(1){
        int eof, i = 0;
        char line[10];
        while(1){
            char tmp = 0 ;
            eof = fscanf(fp, "%c", &tmp);
            line[i++] = tmp;
            //printf("%c", tmp);
            if(tmp == '\n' || eof == EOF) break;
        }
        if(eof == EOF) break;
        strcpy(policy_arr[policy_cnt], line);
        policy_cnt++;
    }
    int spm_param[4];
    spm_param[0] = retention_time;
    spm_param[1] = backup_cycle;
    //spm_param[2] = version_number;
    spm_param[2] = command;
    
    printf_helloworld(global_eid, policy_arr, policy_cnt, spm_param);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    return 0;
}


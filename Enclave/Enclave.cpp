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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void printf_helloworld(char policy_arr[32][1000], int policy_cnt, int spm_param[4])
{
    printf("Hello World\n");
    printf("spm_param : %d %d %d\n", spm_param[0], spm_param[1], spm_param[2]);
    
    //to do : make encrypt msg headed for ssd
    //근데 걍 app에서 하자
    
    //to do : make encrypted new line for policy list
    /*
    int i = 0;
    for(i = 0; i < policy_cnt; i++){
        uint8_t plaintext[1000];
        uint32_t plaintext_len = 1000;
        sgx_unseal_data((sgx_sealed_data_t*)policy_arr[i], NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
        printf("%s\n", plaintext);
    }
    
    sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);*/
    char tmp_policy[1000];
    tmp_policy[0] = spm_param[0];
    tmp_policy[1] = ' ';
    tmp_policy[2] = spm_param[1];
    tmp_policy[3] = 0;
    printf("%s\n",tmp_policy);
    
    char plaintext[1000];
    uint32_t plaintext_len = 1000;
    char sealed_data[1000];
    uint32_t sealed_size = 1000;
    
    sgx_seal_data(0, NULL,plaintext_len, (uint8_t*)tmp_policy, sealed_size, (sgx_sealed_data_t*)sealed_data);
    sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
    
    printf("%s\n",plaintext);
}

//spm_send_cmd 에서 암호화가 됐다고 가정하고 걍 마샬링 잘해서 보내면 될듯

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

//new
#include "sgx_tseal.h"
#include <stdlib.h>
#include <string.h>
#include "sgx_trts.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "tSeal_internal.h"
#include "tseal_migration_attr.h"
//

#define original_len 6
#define encrypt_len 566

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

void printf_helloworld(char policy_arr[32][566], int policy_cnt, int spm_param[4], char*newLine)
{
    printf("Hello World\n");
    printf("spm_param : %d %d %d\n", spm_param[0], spm_param[1], spm_param[3]);
    
    //to do : make encrypt msg headed for ssd
    //근데 걍 app에서 하자
    
    //to do : make encrypted new line for policy list
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    sgx_attributes_t attribute_mask;
    attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    attribute_mask.xfrm = 0x0;
    uint16_t key_policy = SGX_KEYPOLICY_MRSIGNER;

    const sgx_report_t* report = sgx_self_report();
    if (report->body.attributes.flags & SGX_FLAGS_KSS){
        key_policy = SGX_KEYPOLICY_MRSIGNER | KEY_POLICY_KSS;
    }
    
    
    printf("*** policy list ***\n");
    int i = 0;
    for(i = 0; i < policy_cnt; i++){
        uint8_t plaintext[original_len];
        uint32_t plaintext_len = original_len;
        sgx_unseal_data((sgx_sealed_data_t*)policy_arr[i], NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
        printf("%s\n", plaintext);
    }
    printf("*******************\n");
    
    char tmp_policy[original_len];
    tmp_policy[0] = spm_param[0] + '0';
    tmp_policy[1] = ' ';
    tmp_policy[2] = spm_param[1] + '0';
    tmp_policy[3] = ' ';
    tmp_policy[4] = '0';
    tmp_policy[5] = 0;
    printf("tmp_policy : %s\n",tmp_policy);
    
    char plaintext[original_len];
    uint32_t plaintext_len = original_len;
    uint32_t sealed_size = sgx_calc_sealed_data_size(NULL, original_len);
    printf("sealed_size : %d\n", sealed_size);
    char sealed_data[sealed_size];
    //sgx_seal_data(0, NULL,plaintext_len, (uint8_t*)tmp_policy, sealed_size, (sgx_sealed_data_t*)sealed_data);
    sgx_seal_data_ex(key_policy, attribute_mask, TSEAL_DEFAULT_MISCMASK, NULL,
    NULL, plaintext_len, (uint8_t*)tmp_policy, sealed_size, (sgx_sealed_data_t*)sealed_data);
    ocall_pass_string(sealed_data);
    sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
    printf("unsealed : %s\n", plaintext);
    
    //sealing policy example (check perfect excuting)
    /*
    char tmp_policy[1000];
    tmp_policy[0] = spm_param[0] + '0';
    tmp_policy[1] = ' ';
    tmp_policy[2] = spm_param[1] + '0';
    tmp_policy[3] = 0;
    printf("%s\n",tmp_policy);
    
    char plaintext[1000];
    uint32_t plaintext_len = 1000;
    char sealed_data[sizeof(sgx_sealed_data_t) + 1000];
    uint32_t sealed_size = sizeof(sgx_sealed_data_t) + 1000;
    
    sgx_seal_data(0, NULL,plaintext_len, (uint8_t*)tmp_policy, sealed_size, (sgx_sealed_data_t*)sealed_data);
    sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
    printf("%s\n", sealed_data); //why not printed?
    printf("%s\n",plaintext);*/
}

//spm_send_cmd 에서 암호화가 됐다고 가정하고 걍 마샬링 잘해서 보내면 될듯

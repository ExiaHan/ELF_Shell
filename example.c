/*
 * =====================================================================================
 *
 *       Filename:  example.c
 *
 *    Description:  A Simple Example to show how to Shell a ELF File
 *
 *        Version:  1.0
 *        Created:  2015年08月09日 21时43分36秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "elf32.h"

#define MAXLEN 1000
#define PAGESIZE 4096

//The function to decrypt the segment
__attribute__((constructor)) void mydecrypt();

//The section that will be encrypted
__attribute((section("mysection"))) void mysecFunction();

__attribute((section("mysection_data"))) char strMySec[] = "NzTfdujpo";

unsigned long getAddress(char *strName)
{
    char buf[MAXLEN] = {0};
    char *sAddr = NULL;
    unsigned long uRet = 0;
    FILE *fp = NULL;

    sprintf(buf, "/proc/%d/maps", getpid());
    if (!(fp = fopen(buf, "r"))) {
        perror("Error when open file\n");
        return uRet;
    }

    while(fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, strName)) {
            sAddr = strtok(buf, "-");
            uRet = strtol(sAddr, NULL, 16);
            break;
        }
    }

    return uRet;
}

int main(int argc, char **argv)
{
    printf("hello world\n");
    mysecFunction();
    return 0;
}

void mysecFunction()
{
    for (int i = 0; i < strlen(strMySec); i++)
        strMySec[i] -= 1;
    printf("I am in Section %s and data in %s\n", "mysecton", strMySec);
    return;
}

void mydecrypt()
{
    char *strName = "example";
    pElf32_Header  pEhdr = NULL;
    unsigned  uRet;
    unsigned  uBase;
    unsigned  uPageBase;
    unsigned  uSize;
    unsigned  uPageSize;
    int result = 0;

    printf("Before decrypt %s\n", strMySec);
    uRet = getAddress(strName);
    if (uRet == 0) {
        perror("Error When get Baseaddr\n");
        exit(-1);
    }
    pEhdr = (pElf32_Header)uRet;
    uBase = pEhdr->e_shoff;
    uSize = pEhdr->e_shentsize;
    uPageBase = uBase & 0xFFFF1000;
    uPageSize = ((uSize - 1) / 4096  + 1) * 4096;
    //For test
    printf("secton base %x, section size %x, PageBase %x, PageSize %x\n", uBase, uSize, uPageBase, uPageSize);
    result = mprotect((void *)uPageBase, uPageSize, PROT_EXEC|PROT_WRITE);
    if(result == -1){
        printf("%s\n", strerror(errno));
        printf("Error When mprotect\n"), exit(-1);
    }
    for(int i = 0; i < uSize; i++) 
        *((u1 *)uBase + i) ^=  0x1;

    return;
}

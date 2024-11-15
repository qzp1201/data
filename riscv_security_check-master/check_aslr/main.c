#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
    char    buf_ps[1025];
    char    ps[256]="ls";
    FILE*   ptr;

    printf("hello world\n");
    
    ptr = popen(ps,"r");
    if( NULL != ptr ){
        memset(buf_ps,0, 1025);
        while(fgets(buf_ps, 1024, ptr)!=NULL)   
        {
            printf("result:%s\n", buf_ps);
            memset(buf_ps,0, 1025);
           //strcat(result, buf_ps);   
           //if(strlen(result)>1024)   
           //    break;
        }
        pclose(ptr);
    }
    else  
    {   
        printf("popen %s error\n", ps);   
    }   

    return 0;
}
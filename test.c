#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <malloc.h>
#include <sys/mman.h>



int fibonaci(int n)
{
  //printf("stack pointer %p\n", &n);
  if(n == 1) {
  return 1;}
   return fibonaci(n-1)+n ;
  
}


int main(){
     void  *mad;
     int i;
     int j=4;
       void *addr = mmap(0x8000000,1024*1024*1024,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_FIXED,0,0);
        printf("addr success?? %p\n", &addr);
       if ((int)addr == 0x1000) {
        printf("addr success!! %p\n", &addr);
       }
    
    // fibonaci(j);
    
     while(j>0){
       mad = malloc(1024*4);
       
       fibonaci(j+10000);
        j=j+20;
       //printf("%d\t\n", sizeof mad);
       //free(mad);
       sleep(1);
      }
     return 0;
}


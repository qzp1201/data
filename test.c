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
     int j=0;
     unsigned char *p_map;
  
  
    // fibonaci(j);
    
     while(j>0){
       mad = malloc(1024*4);
       p_map = (unsigned char *)mmap(8388608,8388608+j*1024,PROT_READ|PROT_WRITE,MAP_ANONYMOUS,0,0);
       fibonaci(j+10000);
        j=j+20;
       //printf("%d\t\n", sizeof mad);
       //free(mad);
       sleep(1);
      }
     return 0;
}


#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <malloc.h>


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
     int j=1;
  
    // fibonaci(j);
    
     while(j>0){
       mad = malloc(1024*4);
       fibonaci(j+10000);
        j++;
       //printf("%d\t\n", sizeof mad);
       //free(mad);
       sleep(1);
      }
     return 0;
}


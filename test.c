#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <malloc.h>


int fibonaci(int i)
{
   if(i == 0)
   {
      return 0;
   }
   if(i == 1)
   {
      return 1;
   }
   return fibonaci(i-1) + fibonaci(i-2);
}


int main(){
     void  *mad;
     int i;
     int j=1;
  for (i = 0; i < 300; i++)
    {
       fibonaci(i);
    }
     while(j>0){
       mad = malloc(1024*4*j);
        j++;
       printf("%d\t\n", sizeof mad);
       sleep(1);
      }
     return 0;
}


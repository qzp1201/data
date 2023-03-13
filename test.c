#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <malloc.h>


int fibonaci(int count)
{
   if (count <= 0) return;
   fibonaci(count - 1);
}


int main(){
     void  *mad;
     int i;
     int j=1;
  for (i = 0; i < 1024*1024*2; i++)
    {
       fibonaci(i);
    }
     while(j>0){
       mad = malloc(1024*16*j);
        j++;
       printf("%d\t\n", sizeof mad);
       sleep(1);
      }
     return 0;
}


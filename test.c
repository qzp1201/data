#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>


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
     char *mad;
     int i,j=1;
  for (i = 0; i < 10; i++)
    {
       printf("%d\t\n", fibonaci(i));
    }
     while(j>0){
       mad = malloc(sizeof *mad + 1024*1024*j);
        j++;
       printf("%d\t\n", sizeof *mad);
       sleep(1);
      }
     return 0;
}


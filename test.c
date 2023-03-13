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
     int i;
  for (i = 0; i < 10; i++)
    {
       printf("%d\t\n", fibonaci(i));
    }
     while(1){
     mad = malloc(sizeof *mad + 1024);
       sleep(1000);
      }
     return 0;
}


#include "pwnInit.h"
#include "unit.h"
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include "base64.h"

int getIndex(char c, char table[])
{
	int index = 0;
	for(index = 0; index < 16; index++ )
	{
		if( c == table[index] )
			break;
	}
	return index;
}

int strtohex(char *bufstr, char *bufhex, int maxlen)
{
	if( bufstr == NULL || bufhex == NULL )
		return -1;
	char table[] = "0123456789ABCDEF";
	int i = 0;
	for( i = 0; i < maxlen; i++ )
	{
		bufhex[2*i+1] = table[bufstr[i] & 0x0f];
		bufhex[2*i] = table[(bufstr[i]>>4) & 0x0f];
	}
	bufhex[2*i] = 0;
	return 1;
}

int hextostr(char *bufstr, const char *bufhex, int maxlen)
{
	if( bufstr == NULL || bufhex == NULL )
		return -1;
	char table[] = "0123456789ABCDEF";
	int i = 0;
	int index1, index2;
	for( i = 0; i < maxlen; i++ )
	{
		index1 = getIndex(bufhex[2*i], table);
		index2 = getIndex(bufhex[2*i+1], table);
		bufstr[i] = (16*index1 + index2) & 0xff;
	}
	bufstr[i] = 0;
	return 1;
}

int hextostr2(char *bufstr, const char *bufhex, int maxlen)
{
	if( bufstr == NULL || bufhex == NULL )
		return -1;
	char table[] = "0123456789ABCDEF";
	int i = 0;
	int index1, index2;
	for( i = 0; i < maxlen; i++ )
	{
		if( bufhex[2*i] >='0' && bufhex[2*i] <='9' )
		{
			index1 = bufhex[2*i] - '0';
		}
		else if( bufhex[2*i] >='A' && bufhex[2*i] <='F' )
		{
			index1 = bufhex[2*i] - 'A' + 10;
		}
		else if( bufhex[2*i] >='a' && bufhex[2*i] <='f' )
		{
			index1 = bufhex[2*i] - 'a' + 10;
		}
		else
		{
			index1 = 0;
		}
		
		if( bufhex[2*i+1] >='0' && bufhex[2*i+1] <='9' )
		{
			index2 = bufhex[2*i+1] - '0';
		}
		else if( bufhex[2*i+1] >='A' && bufhex[2*i+1] <='F' )
		{
			index2 = bufhex[2*i+1] - 'A' + 10;
		}
		else if( bufhex[2*i+1] >='a' && bufhex[2*i+1] <='f' )
		{
			index2 = bufhex[2*i+1] - 'a' + 10;
		}
		else
		{
			index2 = 0;
		}
		// index1 = getIndex(bufhex[2*i], table);
		// index2 = getIndex(bufhex[2*i+1], table);
		bufstr[i] = (16*index1 + index2) & 0xff;
	}
	bufstr[i] = 0;
	return 1;
}

int version(void)
{
    printf("Version 2024.6.3 !\n");
    return 1;
}

void stack_overflow_base64()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
    data.p = malloc(data.len+1);
    data.p[data.len] = 0;
    read_n(data.p, data.len);
    base64_decode(data.p, data.len, data.buf);
    printf("%s\n", data.p);
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_copy()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	// read_n(data.p, data.len);
	read(STDIN_FILENO, data.p, data.len);
    data.p[data.len] = 0;
    for( data.i = 0; data.i < data.len; data.i++)
    {
		data.buf[data.i] = data.p[data.i];
	}
	data.buf[data.buf[0]] = data.buf[1];
	data.buf[2] = data.buf[data.buf[3]];
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_hex()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(2*data.len+1);
    data.p[data.len] = 0;
    data.len = read_n(data.p, 2*data.len)/2;
    hextostr2(data.buf, data.p, data.len);
    printf("%s\n%s\n", data.p, data.buf);
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_atoi()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		int buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(32);
    data.i = 0;
    for( data.i = 0; data.i < data.len; data.i++)
    {
		data.buf[data.i] = read_int();
	}
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_add()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	read_n(data.p, data.len);
    data.p[data.len] = 0;
    for( data.i = 0; data.i < data.len; data.i++)
    {
		data.buf[data.i] = data.p[data.i] + 18;
	}
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_sub()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	read_n(data.p, data.len);
    data.p[data.len] = 0;
    for( data.i = 0; data.i < data.len; data.i++)
    {
		data.buf[data.i] = data.p[data.i] - 18;
	}
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_and_0xff()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	read_n(data.p, data.len);
    data.p[data.len] = 0;
    for( data.i = 0; data.i < data.len; data.i++)
    {
		data.buf[data.i] = data.p[data.i] & 0xff;
	}
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_and_zero()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	read_n(data.p, data.len);
    data.p[data.len] = 0;
    for( data.i = 0; data.i < data.len; data.i++)
    {
		data.buf[data.i] = data.p[data.i] & 0;
	}
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void stack_overflow_clean()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	read_n(data.p, data.len);
    data.p[data.len] = 0;
    for( data.i = 0; data.i < data.len; data.i++)
    {
		data.buf[data.i] = data.p[data.i] ^ data.p[data.i];
	}
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void call_popen()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	read_n(data.p, data.len);
    data.p[data.len] = 0;
    if(strcmp(data.p, "/bin/sh"))
	{
		FILE *fp = popen(data.p, "r");
	}
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void call_mprotect()
{
	struct dta{
		int len ;
		int i ;
		char *p;
		char buf[0x10];
	};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+1);
	mprotect(data.p, data.len+1, PROT_READ|PROT_WRITE|PROT_EXEC);
	read_n(data.p, data.len);
    data.p[data.len] = 0;
    free(data.p);
   // printf("buf: %s", buf, i, len);
    return;
}

void call_func() 
{
	struct dta{
		int len ;
		int i ;
		char *p;
		int buf[0x10];
	};
	char *argv[10]={"a",NULL};
    struct dta data;
    data.len = read_int();
	data.p = malloc(data.len+100); 
    scanf("%s", data.p );
	if( strcmp(data.p, "hello"))
	{
		sprintf(data.p, "%d",data.len);
	}
	else
	{
		sprintf(data.p, "%d",data.len+1);
	}
	mprotect(data.p, data.len+1, PROT_READ|PROT_WRITE|PROT_EXEC);
	free(data.p);
//	system("hello");
//	popen("hellp","r");
//	execv("hello", argv);
	printf("func addr: %p %p %p %p\n", system, popen, mprotect, execv);
	for(int i = 0; i < 1000000; i++)
	{
		data.len++;
	}
	for(int i = 0; i < 100; i++)
	{
		sleep(1);
		printf("%d\n", i);
	}
	return;
}

void heap_overflow()
{
	int value;
	struct func_table{
		int (*pheret)(void);
		char data[64];
	};
	char buf[1024];
	char *p = (char*)calloc(64, 1);
    struct func_table * myfunc = (struct func_table * )malloc(sizeof(struct func_table));
    myfunc->pheret = version;
	value = read_int();
	if( value > 1024 || value < 0)
		value = 1000;
    read_n(buf, value);
	memcpy(p, buf, value);
	myfunc->pheret();
    return;
}

int main() 
{
    int i; 
    PWNINIT
	printf("func addr: %p %p %p %p %p %p %p %p\n",system, popen, mprotect, execv, atoi, strcmp, malloc, free);
   
    puts("2 heap_over");
    heap_overflow();
    return 0;
}


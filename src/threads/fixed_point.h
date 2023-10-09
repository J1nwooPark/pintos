#define f (1<<14)
#define INT_MAX ((1<<31) - 1) 
#define INT_MIN (-(1<<31)) 

int int_to_fixed(int);
int fp_round_to_zero(int);
int fp_round_to_nearest(int);
int add(int, int);
int sub(int, int);
int add_int(int, int);
int sub_int(int, int);
int mult(int, int);
int mult_int(int, int);
int div(int, int);
int div_int(int, int);

int int_to_fixed(int n)
{
    return n*f;
}

int fp_round_to_zero(int x)
{
    return x/f;
}

int fp_round_to_nearest(int x)
{
    if (x>=0)
        return (x+f/2)/f;
    else
        return (x-f/2)/f;
}

int add(int x, int y)
{
    return x+y;
}

int sub(int x, int y)
{
    return x-y;
}

int add_int(int x, int n)
{
    return x+n*f;
}

int sub_int(int x, int n)
{
    return x-n*f;
}

int mult(int x, int y)
{
    return ((int64_t) x)*y/f;
}

int mult_int(int x, int n)
{
    return x*n;
}

int div(int x, int y)
{
    return ((int64_t) x)*f/y;
}

int div_int(int x, int n)
{
    return x/n;
}
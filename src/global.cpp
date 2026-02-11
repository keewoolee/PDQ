#include "global.h"

// PDQ parameters
int num_records = 16384;
int num_matching = 16;

// BFV context parameters
int ptxt_modulus = 65537;
int degree = 32768;
int MultiplicativeDepth = 18;
int ScalingModSize = 60;
int NumLargeDigits = 4;

// Trace context parameters
int degree_trace = 8192;
int MultiplicativeDepth_trace = 1;
int NumLargeDigits_trace = 2;

// Derived parameters
int degree_half = 0;
int degree_trace_half = 0;
int dim_trace = 0;
int num_ctxts = 0;
int numrow_po2 = 0;
int b_bsgs = 0;
int g_bsgs = 0;

#pragma once

// PDQ parameters
extern int num_records;          // N: total records
extern int num_matching;         // s: max matching records

// BFV context parameters
extern int ptxt_modulus;         // p: plaintext modulus
extern int degree;               // n: ring dimension
extern int MultiplicativeDepth;
extern int ScalingModSize;
extern int NumLargeDigits;

// Trace context parameters
extern int degree_trace;         // n': ring dimension after ring-switch
extern int MultiplicativeDepth_trace;
extern int NumLargeDigits_trace;

// Derived parameters (computed at runtime)
extern int degree_half;
extern int degree_trace_half;
extern int dim_trace;            // degree / degree_trace
extern int num_ctxts;            // ceil(num_records / degree)
extern int numrow_po2;           // next power of 2 >= num_matching
extern int b_bsgs, g_bsgs;       // BSGS parameters for compress

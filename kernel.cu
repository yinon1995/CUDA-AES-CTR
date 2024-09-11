// System includes
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <ctime>

// CUDA runtime
#include <cuda_runtime.h>

// Helper functions and utilities to work with CUDA

#include <device_launch_parameters.h>
#include <device_functions.h>

// Custom header 
#include "kernel.h"
//
#include "128-ctr.cuh"



int main() {

	// AES-128 Exhaustive Search
	main128Ctr();


	return 0;
}

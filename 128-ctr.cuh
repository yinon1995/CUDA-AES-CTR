// System includes
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <ctime>

// CUDA runtime
#include <cuda_runtime.h>


#include <device_launch_parameters.h>
#include <device_functions.h>



// Key expansion from given key set, populate rk[44]
// Host function to perform key expansion for AES encryption
__host__ void keyExpansion(u32* key, u32* rk) {
	// Initialize 4 working registers for the round keys
	u32 rk0, rk1, rk2, rk3;

	// Load the original key into the first 4 round key registers
	rk0 = key[0]; // First 32 bits of the key
	rk1 = key[1]; // Second 32 bits of the key
	rk2 = key[2]; // Third 32 bits of the key
	rk3 = key[3]; // Fourth 32 bits of the key

	// Store the first 4 round keys (which are the original key) into rk array
	rk[0] = rk0;
	rk[1] = rk1;
	rk[2] = rk2;
	rk[3] = rk3;

	// Perform key expansion for each round
	for (u8 roundCount = 0; roundCount < ROUND_COUNT; roundCount++) {
		// Step 1: Get the last 32-bit word (rk3) for the current round
		u32 temp = rk3;

		// Step 2: Apply the key schedule core transformation to the last word
		// The transformation uses the look-up tables (T4_0 to T4_3) to apply 
		// SubBytes operation and XORs with round constants (RCON32)
		rk0 = rk0 ^ T4_3[(temp >> 16) & 0xff] // Extract the third byte of temp
			^ T4_2[(temp >> 8) & 0xff]        // Extract the second byte of temp
			^ T4_1[(temp) & 0xff]             // Extract the first byte of temp
			^ T4_0[(temp >> 24)]              // Extract the fourth byte of temp
			^ RCON32[roundCount];             // Add round constant for the current round

		// Step 3: XOR the new rk0 with the previous rk1, rk2, and rk3 to get new round keys
		rk1 = rk1 ^ rk0; // Generate the next 32-bit round key
		rk2 = rk2 ^ rk1; // Continue the chain of XORs for the next key
		rk3 = rk2 ^ rk3; // Final key update for this round

		// Step 4: Store the newly generated round keys into the rk array
		rk[roundCount * 4 + 4] = rk0;
		rk[roundCount * 4 + 5] = rk1;
		rk[roundCount * 4 + 6] = rk2;
		rk[roundCount * 4 + 7] = rk3;
	}

	// Print all the round keys as 4x4 matrices, three matrices side by side
	for (int round = 0; round < 11; round += 3) {  // Process three rounds at a time
		printf("Rounds %d - %d Keys:\n", round, round + 2);

		// Print rows for each matrix side by side
		for (int row = 0; row < 4; row++) {
			for (int currentRound = round; currentRound < round + 3 && currentRound < 11; currentRound++) {
				for (int col = 0; col < 4; col++) {
					u32 keyWord = rk[currentRound * 4 + col];
					printf("%02x ", (keyWord >> (24 - row * 8)) & 0xff);
				}
				printf("   ");  // Space between matrices
			}
			printf("\n");
		}
		printf("\n");  // Separate rows of 3 matrices
	}

}



// CUDA kernel to perform AES encryption using counter mode with extended shared memory and S-box
__global__ void aesCounterModeKernel(u32* pt, u32* rk, u32* t0G, u32* t4G, u32* range) {

	// Calculate the global thread index within the grid
	int threadIndex = blockIdx.x * blockDim.x + threadIdx.x;

	// Identify the warp thread index and calculate S-box bank index
	int warpThreadIndex = threadIdx.x & 31;
	int warpThreadIndexSBox = warpThreadIndex % S_BOX_BANK_SIZE;

	// <SHARED MEMORY>
	// Declare shared memory arrays for table lookups and round keys
	__shared__ u32 t0S[TABLE_SIZE][SHARED_MEM_BANK_SIZE]; // Shared memory for T0 table
	__shared__ u32 t4S[TABLE_SIZE][S_BOX_BANK_SIZE];      // Shared memory for T4 table (S-box)
	__shared__ u32 rkS[AES_128_KEY_SIZE_INT];             // Shared memory for round keys

	// Populate shared memory with values from global memory
	if (threadIdx.x < TABLE_SIZE) {
		for (u8 bankIndex = 0; bankIndex < SHARED_MEM_BANK_SIZE; bankIndex++) {
			t0S[threadIdx.x][bankIndex] = t0G[threadIdx.x];
		}

		// Load T4 table (S-box) into shared memory for all bank indices
		for (u8 bankIndex = 0; bankIndex < S_BOX_BANK_SIZE; bankIndex++) {
			t4S[threadIdx.x][bankIndex] = t4G[threadIdx.x];
		}

		// Load the AES round keys into shared memory
		if (threadIdx.x < AES_128_KEY_SIZE_INT) {
			rkS[threadIdx.x] = rk[threadIdx.x];
		}

	}
	// </SHARED MEMORY>

	// Synchronize threads to ensure all shared memory is loaded
	__syncthreads();


	// Adjust indexing to ensure that each thread accesses the correct plaintext block
	int ptIndex = threadIndex * 4; // Assuming each thread processes 4 u32 values (128 bits)
	u32 threadRange = *range;

	// Loop over the range for counter mode encryption
	// Increasing the value in the loop condition will result in more block encryptions
	// Each iteration corresponds to encrypting one block of data.
	for (int blockCount = 0; blockCount < 2; blockCount++) {

		if (ptIndex + 3 < *range) { // Bounds check to prevent out-of-range access
			// Load the corresponding plaintext block for this thread
			u32 counter0 = 0xf0f1f2f3U;
			u32 counter1 = 0xf4f5f6f7U;
			u32 counter2 = 0xf8f9fafbU;
			u32 counter3 = 0xfcfdfeffU;

			// Update counter for each block
			counter3 += blockCount;

			u32 s0, s1, s2, s3;
			s0 = counter0;
			s1 = counter1;
			s2 = counter2;
			s3 = counter3;

			// First round just XORs input with key.
			s0 = s0 ^ rkS[0];
			s1 = s1 ^ rkS[1];
			s2 = s2 ^ rkS[2];
			s3 = s3 ^ rkS[3];

			u32 t0, t1, t2, t3;
			for (u8 roundCount = 0; roundCount < ROUND_COUNT_MIN_1; roundCount++) {

				// Table based round function
				u32 rkStart = roundCount * 4 + 4;
				t0 = t0S[s0 >> 24][warpThreadIndex] ^ arithmeticRightShiftBytePerm(t0S[(s1 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[(s2 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[s3 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart];
				t1 = t0S[s1 >> 24][warpThreadIndex] ^ arithmeticRightShiftBytePerm(t0S[(s2 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[(s3 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[s0 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 1];
				t2 = t0S[s2 >> 24][warpThreadIndex] ^ arithmeticRightShiftBytePerm(t0S[(s3 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[(s0 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[s1 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 2];
				t3 = t0S[s3 >> 24][warpThreadIndex] ^ arithmeticRightShiftBytePerm(t0S[(s0 >> 16) & 0xFF][warpThreadIndex], SHIFT_1_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[(s1 >> 8) & 0xFF][warpThreadIndex], SHIFT_2_RIGHT) ^ arithmeticRightShiftBytePerm(t0S[s2 & 0xFF][warpThreadIndex], SHIFT_3_RIGHT) ^ rkS[rkStart + 3];

				s0 = t0;
				s1 = t1;
				s2 = t2;
				s3 = t3;
			}

			// Final round (S-box and XOR)
			s0 = (t4S[t0 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t1 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t2 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t3) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[40];
			s1 = (t4S[t1 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t2 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t3 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t0) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[41];
			s2 = (t4S[t2 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t3 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t0 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t1) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[42];
			s3 = (t4S[t3 >> 24][warpThreadIndexSBox] & 0xFF000000) ^ (t4S[(t0 >> 16) & 0xff][warpThreadIndexSBox] & 0x00FF0000) ^ (t4S[(t1 >> 8) & 0xff][warpThreadIndexSBox] & 0x0000FF00) ^ (t4S[(t2) & 0xFF][warpThreadIndexSBox] & 0x000000FF) ^ rkS[43];

			// Final XOR with plaintext
			u32 finalXor0 = s0 ^ pt[ptIndex + 0];
			u32 finalXor1 = s1 ^ pt[ptIndex + 1];
			u32 finalXor2 = s2 ^ pt[ptIndex + 2];
			u32 finalXor3 = s3 ^ pt[ptIndex + 3];

			// Print the result for the first thread only for each block
			if (threadIndex == 0) {
				printf("Block %d\n", blockCount + 1);
				printf("Init. Counter:    %08x %08x %08x %08x\n", counter0, counter1, counter2, counter3);
				printf("Output Block:     %08x %08x %08x %08x\n", s0, s1, s2, s3);
				printf("Plaintext:        %08x %08x %08x %08x\n", pt[ptIndex + 0], pt[ptIndex + 1], pt[ptIndex + 2], pt[ptIndex + 3]);
				printf("Ciphertext:       %08x %08x %08x %08x\n", finalXor0, finalXor1, finalXor2, finalXor3);
				printf("-------------------------------\n");
			}
		}
	}
}



__host__ int main128Ctr() {
	// Print the header for the AES-128 Counter Mode
	printf("\n");
	printf("########## AES-128 Counter Mode Implementation ##########\n");
	printf("\n");

	// Allocate memory for the plaintext and round keys on the GPU (Managed memory)
	u32* pt, * rk, * roundKeys;
	gpuErrorCheck(cudaMallocManaged(&pt, 4 * sizeof(u32))); // 4 words (128 bits) for plaintext
	gpuErrorCheck(cudaMallocManaged(&rk, 4 * sizeof(u32))); // 4 words (128 bits) for the initial round key
	gpuErrorCheck(cudaMallocManaged(&roundKeys, AES_128_KEY_SIZE_INT * sizeof(u32))); // Total round keys for AES-128

	// Initialize plaintext with specific 128-bit block
	pt[0] = 0x6bc1bee2U;
	pt[1] = 0x2e409f96U;
	pt[2] = 0xe93d7e11U;
	pt[3] = 0x7393172aU;

	// Initialize round key (initial key) for AES-128 encryption
	rk[0] = 0x2B7E1516U;
	rk[1] = 0x28AED2A6U;
	rk[2] = 0xABF71588U;
	rk[3] = 0x09CF4F3CU;

	// Allocate memory for RCON values (used in key expansion)
	u32* rcon;
	gpuErrorCheck(cudaMallocManaged(&rcon, RCON_SIZE * sizeof(u32)));
	for (int i = 0; i < RCON_SIZE; i++) {
		rcon[i] = RCON32[i]; // Load the RCON values
	}

	// Allocate memory for AES S-box and other transformation tables
	u32* t0, * t1, * t2, * t3, * t4, * t4_0, * t4_1, * t4_2, * t4_3;
	gpuErrorCheck(cudaMallocManaged(&t0, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t1, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t2, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t3, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t4, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t4_0, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t4_1, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t4_2, TABLE_SIZE * sizeof(u32)));
	gpuErrorCheck(cudaMallocManaged(&t4_3, TABLE_SIZE * sizeof(u32)));

	// Load transformation tables into the GPU
	for (int i = 0; i < TABLE_SIZE; i++) {
		t0[i] = T0[i];
		t1[i] = T1[i];
		t2[i] = T2[i];
		t3[i] = T3[i];
		t4[i] = T4[i];
		t4_0[i] = T4_0[i];
		t4_1[i] = T4_1[i];
		t4_2[i] = T4_2[i];
		t4_3[i] = T4_3[i];
	}

	// Print the initial state
	printf("-------------------------------\n");
	u32* range = calculateRange(); // Calculate and print the range for the key schedule
	printf("Initial Plaintext              : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
	printf("Initial Key                    : %08x %08x %08x %08x\n", rk[0], rk[1], rk[2], rk[3]);
	printf("-------------------------------\n");

	// Perform key expansion to generate all round keys for AES-128
	keyExpansion(rk, roundKeys);

	// Start the clock to measure time taken for encryption
	clock_t beginTime = clock();

	// Launch the AES-CTR kernel on the GPU, performing encryption
	aesCounterModeKernel << <BLOCKS, THREADS >> > (pt, roundKeys, t0, t4, range);

	// Synchronize device (wait for GPU to finish)
	cudaDeviceSynchronize();

	// Print the time taken for encryption
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	printf("-------------------------------\n");

	// Check if any CUDA errors occurred
	printLastCUDAError();

	// Free the allocated memory for plaintext, keys, and tables
	cudaFree(range);
	cudaFree(pt);
	cudaFree(rk);
	cudaFree(roundKeys);
	cudaFree(t0);
	cudaFree(t1);
	cudaFree(t2);
	cudaFree(t3);
	cudaFree(t4);
	cudaFree(t4_0);
	cudaFree(t4_1);
	cudaFree(t4_2);
	cudaFree(t4_3);
	cudaFree(rcon);

	return 0; // Return 0 to indicate successful execution
}

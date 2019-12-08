
/* hashcracker - for MPI-parallelizing the cracking of passwords with salts
 * Emmy Woods
 * 
 *    before compiling:
 * need OpenSSL and OpenMPI. To install on debian buster: 
 * sudo apt-get install libssl-dev openmpi-bin openmpi-common libopenmpi-dev libopenmpi3 openmpi-doc
 *
 *    compile:
 * mpicc hashcracker.c -lssl -lcrypto -lm -lcrypt -o hashcracker
 * 
 *    run:
* Usage: hashcracker [options] hash...
* Options:
* --hash-function      MD5, SHA-512, or linux shadow password
* --salt               string to use as a salt
* --min                minimum characters for test strings
* --max                maximum characters for test strings
* --ascii-start        ascii character to begin checking with
* --ascii-end          ascii character to end checking with

* example: mpirun -np 2 hashcracker --hash-function MD5 97d986e2afa2c72986972e6433fbeaf9
* 
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <mpi.h>
#include <string.h>
#include <crypt.h>
#include <math.h>
#include <limits.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define SIZE 32 
#define MD 5
#define SHA 512
#define SHADOW 6

// way too many globals for comfort
// I'm trying to keep the stack frame for run_hash tidy, but wow
int min_chars = 4;
int max_chars = 9;
int local_bounds[2];
int start_char = 32; // ascii space
int end_char = 126; // ascii ~
int character_length;
int hash_found = 0; // becomes true when some node has found the answer
char test_char[100] = {0};
char found_char[100] = {0};
int found_rank = -1;
unsigned char hashy[100];
int hash_bytes; // the same as the digest length for the selected hash function
int my_rank;
int world_size;
int worker_found_hash = 0;
unsigned char encoded_value[2000];
MPI_Status status;
MPI_Request request;
int num_runs = 0;
// I'm using numbers to denote hash functions
// 5: MD5, 512: SHA-512, 6: shadow passwords method 6
// I can't use strings because strcmp will slow down run_hash
int hash_function = -1; 
char salt[50];
int salt_length = 0;
int run_benchmark = 0;
int actual_iterations = 0;

/* hash the current string with the user-selected hash function
*/
void hash_string(int offset){
	if (hash_function == 5)
		MD5((unsigned char*)(test_char+offset), max_chars + salt_length - offset, (unsigned char*)&hashy);
		//if (strcmp(test_char, "12345678") == 0) printf("actual answer\n");
	else if (hash_function == 512)
		SHA512((unsigned char*)(test_char+offset), max_chars + salt_length - offset, (unsigned char*)&hashy);
	else if (hash_function == 6){
		strcpy(hashy, crypt(test_char+offset, salt)+20);
	}
}

/* check_hash checks the current test hash against the user-provided hash
 */
int check_hash(){
	int found_answer = 1;
	for (int m = 0; m < hash_bytes; m++){
		if ((unsigned int)encoded_value[m] != (unsigned int)hashy[m]){
			found_answer = 0;
			break;
		}
	}
	return found_answer;
}

/* run_hash hashes every permutation of a string between min_chars and
 * max_chars in length, with salt if applicable, and alerts the other
 * workers if a solution is found.
*/
void run_hash(int start, int end, int level){
	int temp_found = 0;
	int found_answer;
	for(int i = start; i<= end; ++i){
		if (hash_found) return;
		test_char[level+salt_length] = ((char) i); //casting of i to a char type

		//uncomment the line below to see all the tests happen
		//printf("rank is: %d  test char: %s salt: %s\n", my_rank, test_char, salt);
		
		// the j loop makes it so that different substrings of the current string
		// are checked. for example, if the string is aaastring, it will also 
		// check aastring, astring, and string. it only checks the substrings 
		// that are preceeded by the first character of the character set,
		// so as to not recheck things 
		for (int j = 0; j < (max_chars - min_chars + 1); j++){
			if (j > 0 && ((test_char[salt_length+j-1] != start_char) || j > level)) break;
			
			hash_string(j);
			actual_iterations++;
			if (check_hash() == 1){
				hash_found = 1;
				found_rank = my_rank;
				memcpy(found_char,test_char+j+salt_length,sizeof(found_char));
				// alert all the other nodes
				for (int k = 0; k < world_size; k++){
					MPI_Isend(found_char, SIZE, MPI_CHAR, k, 0, MPI_COMM_WORLD, &request);
					MPI_Wait(&request, &status);
				}
				return;
			}
		}
				
		if (level < (max_chars-1)) run_hash(start_char, end_char, level + 1);
	}
	// test to see if any worker as found an answer
	// the Isend doesn't get Irecv'd unless there are tests 
	MPI_Test(&request, &hash_found, &status);
}

/* find_bounds divides up the work by creating bounds within the character set
 * each node will do work with the first character between those bounds
 * this can be further parallelized by dividing things further, as currently
 * it can't be parallelized beyond 95 workers for strings with
 * upper, lower and special characters.
 */
void find_bounds(){
    int bounds[200] = {0}; // array to store the bounds for diving work between nodes

    // node 0 figures out the starting and ending bounds for splitting work among nodes
    if (my_rank == 0){
		int chars_per_node = character_length / world_size;
		int remainder = character_length % world_size;
		int start_bound = 0;
		for (int i = 0; i < world_size * 2; i+=2){
			bounds[i] = start_bound;
			bounds[i+1] = start_bound + chars_per_node - 1;
			if (remainder > 0){
				bounds[i+1] += 1;
				remainder--;
			}
			start_bound = bounds[i+1] + 1;
		}
	}
    
	// scatter the bounds so every node knows what work to do
	MPI_Scatter(bounds, 2, MPI_INT,
		local_bounds, 2, MPI_INT,
			0, MPI_COMM_WORLD);
}

// the hash to compare to is receieved as a string. 
// arg_num specifies which argument contains the string
// store it into encoded_value
void hash_string_to_bin(int arg_num, char *argv[]){
	char temp[5];	
	if (hash_function == 5) hash_bytes = MD5_DIGEST_LENGTH;
	else if (hash_function == 512) hash_bytes = SHA512_DIGEST_LENGTH;
	if (hash_function == 6){
		hash_bytes = 86;
		strcpy(encoded_value, argv[arg_num]); // this one needs to remain a string
	} else {
		for(int i = 0; i < hash_bytes; i++){
			temp[0] = argv[arg_num][i*2];
			temp[1] = argv[arg_num][i*2+1];
			encoded_value[i] = strtol(temp, NULL, 16);
		}
	}
}

// set some variables based on the command line args
int process_args(int argc, char *argv[]){
	if (argc < 4){
		return -1; // too few args
	}
	
	for (int i = 1; i < argc; i++){
		if (strcmp(argv[i], "--hash-function") == 0){
			if (argc == i+1) return -1;
			if (strcmp(argv[i+1], "MD5") == 0) hash_function = 5;
			else if (strcmp(argv[i+1], "SHA-512") == 0) hash_function = 512;
			else if (strcmp(argv[i+1], "shadow") == 0) hash_function = 6;
			else{ 
				return -1;
			}
			i++;
		} else if (strcmp(argv[i], "--min") == 0 || strcmp(argv[i], "--min_characters") == 0) {
			min_chars = (int)strtol(argv[i+1], NULL, 10);
			i++;
		} else if (strcmp(argv[i], "--max") == 0 || strcmp(argv[i], "--max_characters") == 0) {
			max_chars = (int)strtol(argv[i+1], NULL, 10);
			i++;
		} else if (strcmp(argv[i], "--salt") == 0) {
			if (hash_function == 6){
				//strcpy(salt, argv[i+1]);
				sprintf(salt, "$6$%s$", argv[i+1]);
			} else {
				strcpy(test_char, argv[i+1]);
				salt_length = strlen(test_char);
			}
			i++;
		} else if (strcmp(argv[i], "--ascii-start") == 0){
			start_char = argv[i+1][0];
			i++;
		} else if (strcmp(argv[i], "--ascii-end") == 0){
			end_char = argv[i+1][0];
			i++;
		} else if (strcmp(argv[i], "--benchmark") == 0){
			run_benchmark++;
		} else {
			// this must be the hash
			hash_string_to_bin(i, argv);
		}
	}
	if (hash_function == -1) return -1;
	return 0;
}

void print_usage(char program_name[]){
	printf("\nUsage: %s [options] hash...\n", program_name);
	printf("Options:\n");
	printf("%-20s %s\n", "--hash-function", "MD5, SHA-512, or linux shadow password");
	printf("%-20s %s\n", "--salt", "string to use as a salt");
	printf("%-20s %s\n", "--min", "minimum characters for test strings");
	printf("%-20s %s\n", "--max", "maximum characters for test strings");
	printf("%-20s %s\n", "--ascii-start", "ascii character to begin checking with");
	printf("%-20s %s\n", "--ascii-end", "ascii character to end checking with");
	printf("%-20s %s\n\n", "--benchmark" "estimate running time for this job"); 
	printf("example: mpirun -np 4 hashcracker --hash-function MD5 --min 4 97d986e2afa2c72986972e6433fbeaf9\n\n");
}

// takes an integer number of seconds, makes it something human readable
// ex: 5 days, 3 hours, 12 minutes, 32 seconds
void seconds_to_human_readable(unsigned long int seconds){
	if (seconds == 0){
		printf("very fast!\n");
		return;
	}
	if (seconds / 31536000 >= 1){
		printf(" %d years", (seconds / 31536000));
		seconds = seconds % 31536000; // seconds remaining after subtracting years
	}
	if (seconds / 86400 >= 1){
		printf(" %d days", (seconds / 86400));
		seconds = seconds % 86400; 
	}
	if (seconds / 3600 >= 1){
		printf(" %d hours", (seconds / 3600));
		seconds = seconds % 3600;
	}
	if (seconds / 60 >= 1){
		printf(" %d minutes", (seconds / 60));
		seconds = seconds % 60;
	}
	if (seconds > 0) printf(" %d seconds\n", seconds);
	printf("Actual time could be faster if an answer is found\n\n");
	return;
}

// checks how long it takes to run for a bit, and extrapolates
// to find out how long it'll take to run for the whole set of permutations
void benchmark(){
	// save the real values of variables before modifying for benchmark
	int min_temp = min_chars;
	int max_temp = max_chars;
	int start_temp = start_char;
	int end_temp = end_char;
	
	//start_char = 97;
	//end_char = 122;
	
	if (hash_function == MD) min_chars = max_chars = 4;
	else if (hash_function == SHADOW) min_chars = max_chars = 2;
	else min_chars = max_chars = 4;
		
	// iterations is the number of iterations to run for benchmark
	unsigned long long int iterations = pow((end_char - start_char + 1), max_chars);
	unsigned long long total_iterations = 0;

	// start timer
	double time1 = MPI_Wtime();
	
	// run_hash on a small subset of the permutations that need to be brute forced
	run_hash(local_bounds[0] + start_char, local_bounds[1] + start_char, 0);
	MPI_Barrier(MPI_COMM_WORLD);

	// end timer
	double time2 = MPI_Wtime();
	double multiplier = 1.0 / (time2 - time1);
	// how many iterations happen per second?
	unsigned long long int iterations_per_second = (int)((double)iterations * multiplier);
	//if (my_rank == 1) printf("actual its: %d, multiplier: %f, time: %f\n",actual_iterations, multiplier, time2-time1);
	actual_iterations = 0;
	// figure out how many iterations will run when using the real variables
	for (int i = min_temp; i <= max_temp; i++){
		if ((total_iterations + pow((end_temp - start_temp + 1), i)) >= ULLONG_MAX){ // / (end_temp-start_temp+1)){
			total_iterations = ULLONG_MAX;
			if (my_rank == 0) printf("Unable to estimate running time. Not in our lifetimes.\n");
			return;
		}
		total_iterations += pow((end_temp - start_temp + 1), i);
	}

	// extrapolate the time to run_hash to the full set of permutations
	unsigned long long int total_time = total_iterations / iterations_per_second;
	//if (my_rank == 0) printf("its: %llu, total its: %llu, its per sec: %d\n", iterations, total_iterations, iterations_per_second);


	if (my_rank == 0){
		printf("\nEstimated running time:");
		seconds_to_human_readable(total_time);
	}
	
	// restore the variables
	min_chars = min_temp;
	max_chars = max_temp;
	start_char = start_temp;
	end_char = end_temp;
}

int main(int argc, char *argv[]){
	unsigned long ans = 0;
	MPI_Init(NULL, NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &world_size);
	if (process_args(argc, argv) < 0){
		if (my_rank == 0) print_usage(argv[0]);
		return -1;
	}
	character_length = end_char - start_char + 1;
	// be ready to receieve an answer from any of the nodes
	MPI_Irecv(found_char,SIZE, MPI_CHAR,MPI_ANY_SOURCE,0,MPI_COMM_WORLD,
				&request);

	find_bounds(my_rank, world_size);
    
	if (run_benchmark > 0) benchmark();
	// finish the benchmark before beginning
	MPI_Barrier(MPI_COMM_WORLD);

	run_hash(local_bounds[0] + start_char, local_bounds[1] + start_char, 0);
	
	// need a barrier here to make sure all nodes have finished
	MPI_Barrier(MPI_COMM_WORLD);
	// final test to see if there's an answer
	MPI_Test(&request, &hash_found, &status);
	
	if (my_rank == 0 && strlen(found_char) > 0){
		printf("The answer is: %s\n", found_char);
	} else if (my_rank == 0) {
		printf("Unable to find the answer\n");
	}
	//if (my_rank == 0) printf("actual iterations: %d\n", actual_iterations);

	MPI_Finalize();
	return 0;
}

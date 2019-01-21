#include "dispatch.h" //own defs
#include "analysis.h" //for analyse

#include <pcap.h>

/* The arguments that will be passed into the function, required by p_thread
*/
struct args {
	const unsigned char *packet;
	int verbose;
};

/* Thunking function that unpacks the thread arguments and frees the space used by thread afterwards
*/
void *tanalysis(void *targs) {
	struct args *targuments = (struct thread_args *) targs; //redeclare the type of the argument struct
	const unsigned char *packet = targuments->packet;  //unpacks the packet argument
	int verbose = targuments->verbose;  //unpacks the verbose argument
	analyse(packet, verbose);    //runs the thread analysis thread
	pthread_exit(NULL);       //exits the thread
	free(&targuments);       //frees the space used bu the targuments structure of the thread
	free(&targs);            //frees the space used by the targ structure of the thread
	return NULL;
}

/* Creates threads and dispatches the analysis function to each
*/
void dispatch(const unsigned char *packet, int verbose) {
	pthread_t thread; //declare the thread
	struct args targs = {packet, verbose}; //set the thread arguments
	pthread_create(&thread, NULL, &tanalysis, (void *)&targs);  //create a thread with the arguments
	pthread_join(thread, (void **)NULL);  //waits for the thread to end
}


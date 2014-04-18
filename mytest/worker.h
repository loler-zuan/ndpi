struct worker_ctl
{
	pthread_t pid;
	pthread_mutex_t mutex;
	int flags;
};


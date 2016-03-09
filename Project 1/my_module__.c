#define _XOPEN_SOURCE 500

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <asm/current.h>
#include <asm/unistd.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <asm/system.h>
#include<linux/slab.h>
#include<linux/socket.h>
#include<linux/in.h>
#include<net/sock.h>
#include<linux/file.h>
#include<linux/net.h>
#include <linux/proc_fs.h>
/* for proc file */
#define procfs_name "helloworld"

struct proc_dir_entry *Our_Proc_File=NULL;
int my_proc_write(struct file *file, const char __user *buffer, unsigned long count,void *data);
int proc_write(struct file *filp, const char  *buffer, unsigned long count,void *data);
void write_proc_file(char *buffer,char *path);
/******* for Hash Function  *******/
struct entry_s {
	char *key;
	char *value;
	struct entry_s *next;
};

typedef struct entry_s entry_t;

struct hashtable_s {
	int size;
	struct entry_s **table;	
};

typedef struct hashtable_s hashtable_t;
char *strdup(const char *str);
void ht_create( int size );
void ht_set( hashtable_t *hashtable, char *key, char *value );
char *ht_get( hashtable_t *hashtable, char *key);
int ht_hash( hashtable_t *hashtable, char *key );

hashtable_t *hashtable;//=ht_create( 65536 );

/******* for Hash Function  *******/

/***** for config file data ***********/
char *DIR[10];
char temp[30];
void config_file();
int streql(char DIR[], char filename[], int len);
/***** for config file data ***********/
char USER_NAME[7]="USRNAM\0";
char USER_TIME[11]="###:##:###";
char log_filename[11]="##_##_####";
unsigned long *syscall_table = (unsigned long *) 0xffffffff81600340;
void print_time(char char_time[]);
int get_username(char *);


void write_file(char *,char *);
void write_file1(char *,char *);

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage size_t (*original_read)(int, char *, size_t);
asmlinkage int (*original_close)(unsigned int);
asmlinkage int (*original_open)(const char __user *, int, int);
asmlinkage int (*original_open_temp)(const char __user *, int, int);
asmlinkage int (*original_socketcall)(int call, unsigned long __user *args);
asmlinkage int (*original_getsockname)(int,struct sockaddr __user *,int *);
asmlinkage int (*original_getpeername)(int,struct sockaddr __user *,int *);
asmlinkage int (*original_fstat) (int,struct stat *);
asmlinkage long (*original_connect)(int, struct sockaddr __user *, int);
asmlinkage long (*original_accept)(int, struct sockaddr __user *, int __user *);
asmlinkage long (*original_sendto)(int, void __user *, size_t, unsigned,struct sockaddr __user *, int);
asmlinkage long (*original_recvfrom)(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *);
asmlinkage ssize_t (*original_readlink)(const char __user *,char __user *, size_t bufsiz);

asmlinkage int new_open(const char __user *, int, int);

void print_time(char []);
int get_username(char *);
void write_file(char *,char *);
char *inet_ntoa(struct in_addr inn);

short unsigned int my_ntoh(short unsigned int src_port);


/* ****************** hash table  ************************** */
char *strdup(const char *str)
{
    int n = strlen(str) + 1;
    char *dup = (char *)kmalloc(n, GFP_ATOMIC);
    if(dup)
    {
        strcpy(dup, str);
    }
    return dup;
}




/* Create a new hashtable. */
void ht_create( int size ) {

	hashtable = NULL;
	int i;
	
	if( size < 1 ) return NULL;
	/* Allocate the table itself. */
	if( ( hashtable = kmalloc( sizeof( hashtable_t ), GFP_ATOMIC ) ) == NULL ) {
		return NULL;
	}
	/* Allocate pointers to the head nodes. */
	if( ( hashtable->table = kmalloc( sizeof( entry_t * ) * size, GFP_ATOMIC ) ) == NULL ) {
		return NULL;
	}

	for( i = 0; i < size; i++ ) {
		hashtable->table[i] = NULL;
	}

	hashtable->size = size;

	//return hashtable;	
	
}

/* Hash a string for a particular hash table. */
int ht_hash( hashtable_t *hashtable, char *key ) {

	unsigned long int hashval;
	int i = 0;

	/* Convert our string to an integer */
	while( hashval < ULONG_MAX && i < strlen( key ) ) {
		hashval = hashval << 8;
		hashval += key[ i ];
		i++;
	}

	return hashval % hashtable->size;
}

/* Create a key-value pair. */
entry_t *ht_newpair( char *key, char *value ) {
	entry_t *newpair;

	if( ( newpair = kmalloc( sizeof( entry_t ),GFP_ATOMIC ) ) == NULL ) {
		return NULL;
	}

	if( ( newpair->key = strdup( key ) ) == NULL ) {
		return NULL;
	}

	if( ( newpair->value = strdup( value ) ) == NULL ) {
		return NULL;
	}

	newpair->next = NULL;

	return newpair;
}

/* Insert a key-value pair into a hash table. */
void ht_set(hashtable_t *hashtable,char *key, char *value ) {
	int bin = 0;
	entry_t *newpair = NULL;
	entry_t *next = NULL;
	entry_t *last = NULL;

	bin = ht_hash( hashtable, key );

	next = hashtable->table[ bin ];

	while( next != NULL && next->key != NULL && strcmp( key, next->key ) > 0 ) {
		last = next;
		next = next->next;
	}

	/* There's already a pair.  Let's replace that string. */
	if( next != NULL && next->key != NULL && strcmp( key, next->key ) == 0 ) {

		kfree( next->value );
		next->value = strdup( value );

	/* Nope, could't find it.  Time to grow a pair. */
	} else {
		newpair = ht_newpair( key, value );

		/* We're at the start of the linked list in this bin. */
		if( next == hashtable->table[ bin ] ) {
			newpair->next = next;
			hashtable->table[ bin ] = newpair;
	
		/* We're at the end of the linked list in this bin. */
		} else if ( next == NULL ) {
			last->next = newpair;
	
		/* We're in the middle of the list. */
		} else  {
			newpair->next = next;
			last->next = newpair;
		}
	}
}

/* Retrieve a key-value pair from a hash table. */
char *ht_get( hashtable_t *hashtable, char *key ) {
	int bin = 0;
	entry_t *pair;

	bin = ht_hash( hashtable, key );

	/* Step through the bin, looking for our value. */
	pair = hashtable->table[ bin ];
	while( pair != NULL && pair->key != NULL && strcmp( key, pair->key ) > 0 ) {
		pair = pair->next;
	}

	/* Did we actually find anything? */
	if( pair == NULL || pair->key == NULL || strcmp( key, pair->key ) != 0 ) {
		return NULL;

	} else {
		return pair->value;
	}
	
}


/* ****************** hash table end ************************** */

asmlinkage size_t our_sys_write(int fd,char __user *buf,size_t count)
{
	
	char fileinfo_buff[200], fdbuffer[120], cntbuffer[200],path[120],readfilepath[100],  fdkey[12];
	char procPath[120];
	int ret;
	print_time(USER_TIME);			// Get Current Time
	strcpy(fileinfo_buff,USER_TIME+1);	// Store Time in Log Array
	ret=get_username(USER_NAME);
	if(ret < 0)
	{ 
		//printk(KERN_ALERT "\n error in get_username");
	}
	else
	{ 
		strcat(fileinfo_buff,USER_NAME);
	}
	sprintf(fdkey,"%s%d",USER_NAME,fd);
	//printk( KERN_ALERT "ReadFilename: %s\n", ht_get( hashtable, fdkey ) );
	sprintf(readfilepath, "%s ",ht_get( hashtable, fdkey ));


	int flag=0;
	flag=streql(DIR[0], readfilepath,strlen(DIR[0]));
	if(flag>=1)
	{

		strcat(fileinfo_buff,"# Write ");

		sprintf(fdbuffer, "# %d", fd);
		strcat(fileinfo_buff,fdbuffer);

		sprintf(cntbuffer, "# %d # ", count);
		strcat(fileinfo_buff,cntbuffer);

		strcat(fileinfo_buff,readfilepath);

		strcat(fileinfo_buff,"\n");

		strcpy(path,"/home/hetalsavaliya/output/file/");
		strcat(path,log_filename);
		if((USER_NAME[0]>='A' && USER_NAME[0]<='Z')||(USER_NAME[0]>='a' && USER_NAME[0]<='z'))
		{
			write_file(fileinfo_buff,path);
			
			strcpy(procPath,"/proc/helloworld");
			write_proc_file(fileinfo_buff,path);
		}

		printk("\n write intercepted");
		
		return original_write(fd,buf,count);

		
	}
	else
	{
		return original_write(fd,buf,count);
	}
}

asmlinkage size_t our_sys_read(int fd,char __user *buf,size_t count)
{

	char fileinfo_buff[300], fdbuffer[100], cntbuffer[100],path[120], readfilepath[100],  fdkey[12];
	int ret;
	char filepath[100];
	ssize_t len=0;

	print_time(USER_TIME);			// Get Current Time
	strcpy(fileinfo_buff,USER_TIME+1);	// Store Time in Log Array
	ret=get_username(USER_NAME);
	if(ret < 0)
	{ 
		printk(KERN_ALERT "\n error in get_username");
	}
	else
	{ 
		strcat(fileinfo_buff,USER_NAME);
	}
	sprintf(fdkey,"%s%d",USER_NAME,fd);
	//printk( KERN_ALERT "ReadFilename: %s\n%d", ht_get( hashtable, fdkey ), fd );
	sprintf(readfilepath, "%s ",ht_get( hashtable, fdkey ));
	
	

	int flag=0;
	//flag=streql(DIR[0], readfilepath,strlen(DIR[0]));
	flag=streql(DIR[0], readfilepath,strlen(DIR[0]));
	/*
	if(flag!=1)
		printk(KERN_ALERT "\n both strings are not equal:%s and %s", DIR[0],readfilepath);
	else
		printk(KERN_ALERT "\n both strings are equal:%s and %s", DIR[0],readfilepath);
	*/
	if(flag>=1)
	{

		strcat(fileinfo_buff,"# Read");

		sprintf(fdbuffer, "# %d", fd);
		strcat(fileinfo_buff,fdbuffer);

		sprintf(cntbuffer, "# %d # ", count);
		strcat(fileinfo_buff,cntbuffer);
	
		
		strcat(fileinfo_buff,readfilepath);

	
		strcat(fileinfo_buff,"\n");

		strcpy(path,"/home/hetalsavaliya/output/file/");
		strcat(path,log_filename);
		if((USER_NAME[0]>='A' && USER_NAME[0]<='Z')||(USER_NAME[0]>='a' && USER_NAME[0]<='z'))
		{
			write_file(fileinfo_buff,path);
		}

		//printk("Read intercepted \n");
		return original_read(fd,buf,count);
	}
	else
	{
		return original_read(fd,buf,count);
	}
}
asmlinkage long new_connect(int fd, struct sockaddr __user *buff1, int flag)
{
	int ret, ret1, ret2;
	struct sockaddr_in getsock, getpeer;
	struct sockaddr_in *getsock_p, *getpeer_p;
	int socklen;
	char netinfo_buff[200], path[120];
	char buff[100];

	socklen=sizeof(getsock);
	mm_segment_t old_fs=get_fs();
	set_fs(KERNEL_DS);
	ret1=original_getsockname(fd,(struct sockaddr *)&getsock,&socklen);
	getsock_p=&getsock;
	ret2=original_getpeername(fd,(struct sockaddr *)&getpeer,&socklen);
	getpeer_p=&getpeer;

	set_fs(old_fs);
	printk("\nret1 is %d %d",ret1, ret2);
	if(getsock.sin_family==2)
	{
		print_time(USER_TIME);
		strcpy(netinfo_buff,USER_TIME+1);
		ret=get_username(USER_NAME);
		if(ret < 0)
		{ 
			printk(KERN_ALERT "\n error in get_username");
		}
		else
		{ 
			strcat(netinfo_buff,USER_NAME);
		}
		snprintf(buff,9,"#%s","Connect");
		strcat(netinfo_buff,buff);
		snprintf(buff,18, "#%s",inet_ntoa(getsock.sin_addr));
		strcat(netinfo_buff,buff);
		snprintf(buff,10,"#%u",my_ntoh(getsock.sin_port));
		strcat(netinfo_buff,buff);
		snprintf(buff,18,"#%s",inet_ntoa(getpeer.sin_addr));
		strcat(netinfo_buff,buff);
		snprintf(buff,10,"#%u\n",my_ntoh(getpeer.sin_port));

		strcat(netinfo_buff,buff);
		strcpy(path,"/home/hetalsavaliya/output/network/");
		strcat(path,log_filename);
		write_file(netinfo_buff,path);
	
	}
	return original_connect(fd,buff1,flag);
}
asmlinkage long new_accept(int fd, struct sockaddr __user *buff1, int __user *buff2)
{
	int ret, ret1, ret2,fc;
	struct sockaddr_in getsock, getpeer;
	struct sockaddr_in *getsock_p, *getpeer_p;
	int socklen;
	char netinfo_buff[200], path[120];
	char buff[100];
	socklen=sizeof(getsock);
	mm_segment_t old_fs=get_fs();
	set_fs(KERNEL_DS);
	ret1=original_getsockname(fd,(struct sockaddr *)&getsock,&socklen);
	getsock_p=&getsock;
	ret2=original_getpeername(fd,(struct sockaddr *)&getpeer,&socklen);
	getpeer_p=&getpeer;
	set_fs(old_fs);
	printk("\nret1 is %d %d",ret1, ret2);
	if(getsock.sin_family==2)
	{
		print_time(USER_TIME);
		strcpy(netinfo_buff,USER_TIME+1);
		ret=get_username(USER_NAME);
		if(ret < 0)
		{ 
			printk(KERN_ALERT "\n error in get_username");
		}
		else
		{ 
			strcat(netinfo_buff,USER_NAME);
		}
		snprintf(buff,8,"#%s","Accept");
		strcat(netinfo_buff,buff);
		snprintf(buff,18, "#%s",inet_ntoa(getsock.sin_addr));
		strcat(netinfo_buff,buff);
		snprintf(buff,10,"#%u",my_ntoh(getsock.sin_port));
		strcat(netinfo_buff,buff);
		snprintf(buff,18,"#%s",inet_ntoa(getpeer.sin_addr));
		strcat(netinfo_buff,buff);
	
		snprintf(buff,10,"#%u\n",my_ntoh(getpeer.sin_port));
		strcat(netinfo_buff,buff);
	
		strcpy(path,"/home/hetalsavaliya/output/network/");
		strcat(path,log_filename);
		write_file(netinfo_buff,path);
	}
	return original_accept(fd,buff1,buff2);
}
asmlinkage long new_sendto(int fd, void __user *buff1, size_t len, unsigned flags, struct sockaddr __user *addr, int addr_len)
{
	int ret, ret1, ret2,fc;
	struct sockaddr_in getsock, getpeer;
	struct sockaddr_in *getsock_p, *getpeer_p;
	int socklen;
	char netinfo_buff[200], path[120];
	char buff[100];
	socklen=sizeof(getsock);
	mm_segment_t old_fs=get_fs();
	set_fs(KERNEL_DS);
	ret1=original_getsockname(fd,(struct sockaddr *)&getsock,&socklen);
	getsock_p=&getsock;
	ret2=original_getpeername(fd,(struct sockaddr *)&getpeer,&socklen);
	getpeer_p=&getpeer;
	set_fs(old_fs);
	printk("\nret1 is %d %d",ret1, ret2);

	if(getsock.sin_family==2)
	{
		//printk("Hi\n");
		print_time(USER_TIME);
		strcpy(netinfo_buff,USER_TIME+1);
		ret=get_username(USER_NAME);
		if(ret < 0)
		{ 
			printk(KERN_ALERT "\n error in get_username");
		}
		else
		{ 
			strcat(netinfo_buff,USER_NAME);
		}
		snprintf(buff,8,"#%s","SEND");
		strcat(netinfo_buff,buff);
		snprintf(buff,18, "#%s",inet_ntoa(getsock.sin_addr));
		strcat(netinfo_buff,buff);
		snprintf(buff,10,"#%u",my_ntoh(getsock.sin_port));
		strcat(netinfo_buff,buff);
		snprintf(buff,18,"#%s",inet_ntoa(getpeer.sin_addr));
		strcat(netinfo_buff,buff);

		snprintf(buff,10,"#%u\n",my_ntoh(getpeer.sin_port));
		strcat(netinfo_buff,buff);

		strcpy(path,"/home/hetalsavaliya/output/network/");
		strcat(path,log_filename);
		write_file(netinfo_buff,path);

	}
	return original_sendto(fd,buff1,len,flags,addr,addr_len);
}
asmlinkage long new_recvfrom(int fd, void __user *buff1, size_t len, unsigned flags, struct sockaddr __user *ar, int __user *buff2)
{
	int ret, ret1, ret2,fc;
	struct sockaddr_in getsock, getpeer;
	struct sockaddr_in *getsock_p, *getpeer_p;
	int socklen;
	char netinfo_buff[200], path[120];
	char buff[100];
	socklen=sizeof(getsock);
	mm_segment_t old_fs=get_fs();
	set_fs(KERNEL_DS);
	ret1=original_getsockname(fd,(struct sockaddr *)&getsock,&socklen);
	getsock_p=&getsock;
	ret2=original_getpeername(fd,(struct sockaddr *)&getpeer,&socklen);
	getpeer_p=&getpeer;
	set_fs(old_fs);
	printk("\nret1 is %d %d",ret1, ret2);
	if(getsock.sin_family==2)
	{
		printk("Hi\n");
		print_time(USER_TIME);
		strcpy(netinfo_buff,USER_TIME+1);
		ret=get_username(USER_NAME);
		if(ret < 0)
		{ 
			printk(KERN_ALERT "\n error in get_username");
		}
		else
		{ 
			strcat(netinfo_buff,USER_NAME);
		}
		snprintf(buff,9,"#%s","RECEIVE");
		strcat(netinfo_buff,buff);
		snprintf(buff,18, "#%s",inet_ntoa(getsock.sin_addr));
		strcat(netinfo_buff,buff);
		snprintf(buff,10,"#%u",my_ntoh(getsock.sin_port));
		strcat(netinfo_buff,buff);
		snprintf(buff,18,"#%s",inet_ntoa(getpeer.sin_addr));
		strcat(netinfo_buff,buff);
		snprintf(buff,10,"#%u\n",my_ntoh(getpeer.sin_port));

		strcat(netinfo_buff,buff);

		strcpy(path,"/home/hetalsavaliya/output/network/");
		strcat(path,log_filename);
		write_file(netinfo_buff,path);
	}
	return (*original_recvfrom)(fd,buff1,len,flags,ar,buff2);
}
asmlinkage int new_open(const char __user *filename, int flags, int mode)
{
	char fileinfo_buff[200], path[120],procPath[120],fdkey[12];
	int ret,fd;
	int flag=0;
	
	flag=streql(DIR[0], filename,strlen(DIR[0]));
	
	//if(flag!=1)
	//	printk(KERN_ALERT "\n both strings are not equal:%s and %s", DIR[0],filename);
	//else
	//	printk(KERN_ALERT "\n both strings are equal:%s and %s", DIR[0],filename);
	
	
	if(flag>=1)
	{
		print_time(USER_TIME);			// Get Current Time
		strcpy(fileinfo_buff,USER_TIME+1);	// Store Time in Log Array
		ret=get_username(USER_NAME);
		if(ret < 0)
		{ 
			printk(KERN_ALERT "\n error in get_username");
		}
		else
		{ 
			strcat(fileinfo_buff,USER_NAME);
		}
		strcat(fileinfo_buff,"# Open");
		if(flags & (O_WRONLY|O_APPEND))
		{
			strcat(fileinfo_buff,"# WR #");
		}
		else
		{
			strcat(fileinfo_buff,"# RD #");
		}
	
		strcat(fileinfo_buff,filename);
		strcat(fileinfo_buff,"\n");
		strcpy(path,"/home/hetalsavaliya/output/file/");
		strcat(path,log_filename);
		if((USER_NAME[0]>='A' && USER_NAME[0]<='Z')||(USER_NAME[0]>='a' && USER_NAME[0]<='z'))
		{
			strcpy(procPath,"/proc/helloworld");
			write_proc_file(fileinfo_buff,path);

			write_file(fileinfo_buff,path);
		}
		fd= (*original_open)(filename, flags, mode);
	
		sprintf(fdkey,"%s%d",USER_NAME,fd); // Hash key: username+fd
		ht_set(hashtable,fdkey, filename ); // Add key-value into hash table
	}
	else
	{
	 	fd= (*original_open)(filename, flags, mode);
	}
	
	//config_file();
	return fd;
}
int streql(char DIR[], char filename[], int len)
{
	int i=0;
	while(i<len-1)
	{
		//printk(KERN_ALERT "\n string:%c and %c", DIR[i],filename[i]);
		if(DIR[i]!=filename[i])
			return 0;
		i++;
	}
	return 1;
}	

void write_file(char *buffer,char *path)
{
	mm_segment_t old_fs;
	int fd;
	old_fs=get_fs();
	set_fs(KERNEL_DS);
	fd = original_open(path, O_WRONLY|O_CREAT|O_APPEND,0777);
	// printk(" %d %s",fd,buffer);
	if(fd >= 0)
	{
		original_write(fd,buffer,strlen(buffer));
		original_close(fd);
	}
	else
	{
		//printk(KERN_ALERT "\n Errro in write_file() while opening a file");
	}
	set_fs(old_fs);
	return;
}
void write_proc_file(char *buffer,char *path)
{
	
	
		//proc_write(path,buffer,strlen(buffer), NULL);
		
		
	return;
}
void config_file()
{
	mm_segment_t old_fs;
	int fd;
	int count;
	char config_bfr[30];
	old_fs=get_fs();
	set_fs(KERNEL_DS);
	fd = original_open("/home/hetalsavaliya/lkm/config.txt", O_RDONLY,0644);
	// printk(" %d %s",fd,buffer);
	if(fd >= 0)
	{
		struct stat fileStat;
		if(original_fstat(fd,&fileStat)!=0)
			printk(KERN_ALERT "\n cannot Open config file:%d",fileStat.st_size );
		else
			printk(KERN_ALERT "\n Open config file:%d",fileStat.st_size );
		int filesize=fileStat.st_size;
		
		count=original_read(fd, config_bfr, filesize);
		
		snprintf(temp, count+1, config_bfr);
		if(DIR[0]==NULL)
			DIR[0]=(char *)kmalloc(count+1,GFP_ATOMIC);

		strcpy(DIR[0],temp);
		//sprintf(DIR[0],"%s",config_bfr);
		printk("\nconfig data:%s", DIR[0]);
		//printk("\n length of data:%d-%d",strlen(temp), count);
		original_close(fd);
	}
	else
	{
		printk(KERN_ALERT "\n Errro in config opening a file");
	}
	set_fs(old_fs);
	return;
}

char tx_buffer[100];

static int proc_max_size=100;
static unsigned long buffer_size=0;

int proc_write(struct file *filp, const char  *buffer, unsigned long count,void *data)
{
	
	if(count>proc_max_size)
		count=proc_max_size;
	if(copy_from_user(tx_buffer, buffer, count))
	{
		printk(KERN_ALERT "\n Errro in write_proc_file() while opening a file");
		return -EFAULT;
	}
	printk(KERN_ALERT "\n written in file");
	int my_data=0;
	
	printk(KERN_ALERT "\nuser has sent the value of %s\n", tx_buffer);
	buffer_size=count;
	return count;
	
}
int proc_read(char *buffer, char **buffer_location, off_t offset, int buffer_length,int *eof, void *data)
{
	int ret;
	if(offset>0)
	{
		ret=0;
	}
	else
	{
		memcpy(buffer, tx_buffer, buffer_size);
		ret=buffer_size;
	}
	return ret;
}
int my_proc_write(struct file *file, const char __user *buffer, unsigned long count,void *data)
{

	
	char *page;
	int size=sizeof(int);
	int my_data=0;
	// make sure data is in right size
	if(count<size)
	{
		return -EINVAL;
	}
	page=(char *) vmalloc(size);
	if(!page)
		return -ENOMEM;
	
	//copy the data from user space
	if(copy_from_user(page, buffer, size))
	{
		
		vfree(page);
		return -EFAULT;
	}
	sscanf(page, "%d",&my_data);
	printk(KERN_ALERT "\nuser has sent the value of %d\n", my_data);
	vfree(page);
	return count;
}
int my_proc_read(char *buf, char **start, off_t offset, int count,int *eof, void *data)
{
 	int len=0;
	len+=sprintf(buf+len, "my first line of proc data\n");
	len+=sprintf(buf+len, "my SECOND line of proc data\n");
	if(len<=count+offset)
		*eof=1;
	*start=buf+offset;
	
	len-=offset;
	if(len>count)
		len=count;
	if(len<0)
		len=0;

	return len;

}
static int init(void)
{
	printk("\n******************************************Module starting...***************************************\n");
	ht_create(100);
	write_cr0 (read_cr0 () & (~ 0x10000));
	original_write= (void *)syscall_table[__NR_write];
	original_read=(void *)syscall_table[__NR_read];
	original_close=(void *)syscall_table[__NR_close];
	original_open=(void *)syscall_table[__NR_open];
	original_getsockname=(void *)syscall_table[__NR_getsockname];
	original_getpeername=(void *)syscall_table[__NR_getpeername];
	original_fstat=(void *)syscall_table[__NR_fstat];
	original_connect=(void *)syscall_table[__NR_connect];
	original_accept=(void *)syscall_table[__NR_accept];
	original_sendto=(void *)syscall_table[__NR_sendto];
	original_recvfrom=(void *)syscall_table[__NR_recvfrom];
	original_readlink=(void *)syscall_table[__NR_readlink];

	syscall_table[__NR_open]=new_open;
	syscall_table[__NR_write]=our_sys_write;
	syscall_table[__NR_read]=our_sys_read;
	syscall_table[__NR_sendto]=new_sendto;
	syscall_table[__NR_recvfrom]=new_recvfrom;
	syscall_table[__NR_connect]=new_connect;
	syscall_table[__NR_accept]=new_accept;
	write_cr0 (read_cr0 () | 0x10000);
	config_file();
	/* create a Proc file */	
	Our_Proc_File=create_proc_entry(procfs_name,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, NULL);
	if(Our_Proc_File)
	{
		
		//Our_Proc_File->mode=S_IFREG | S_IRUGO;
		//Our_Proc_File->size=37;
		Our_Proc_File->read_proc=proc_read;//my_proc_read;
		Our_Proc_File->write_proc=proc_write;//my_proc_write;
		//Our_Proc_File->uid=0;
		printk(KERN_ALERT "\n proc file is created");
		
		
	}
	return 0;
}
static void exit(void)
{
	write_cr0 (read_cr0 () & (~ 0x10000));
	syscall_table[__NR_open]=original_open;
	syscall_table[__NR_write]=original_write;
	syscall_table[__NR_read]=original_read;
	syscall_table[__NR_sendto]=original_sendto;
	syscall_table[__NR_recvfrom]=original_recvfrom;
	syscall_table[__NR_connect]=original_connect;
	syscall_table[__NR_accept]=original_accept;
	write_cr0 (read_cr0 () | 0x10000);
	kfree(hashtable->table);
	kfree(hashtable);
	remove_proc_entry(procfs_name, NULL);
	printk("**********************************************Module exiting*********************************************\n");
	return;
}

short unsigned int my_ntoh(short unsigned int src_port)
{
	short unsigned int t,t1,t2;
	t = (src_port >> 8);
	t1 = (src_port << 8);
	t2 = t|t1;
	return(t2);
}
char *inet_ntoa(struct in_addr inn)
{
	static char m[18];
	register char *m1;
	m1 = (char *)&inn;
	#define UCC(m) (((int)m)&0xff)
	(void)snprintf(m, sizeof(m),"%u.%u.%u.%u", UCC(m1[0]), UCC(m1[1]), UCC(m1[2]), UCC(m1[3]));
	return(m);
}
void print_time(char char_time[])
{
	struct timeval my_tv;
	int sec, hr, min, tmp1, tmp2;
	int days,years,days_past_currentyear;
	int i=0,month=0,date=0;
	unsigned long get_time;
	char_time[11]="#00:00:00#";	//
	do_gettimeofday(&my_tv);	// Get System Time From Kernel Mode
	get_time = my_tv.tv_sec;	// Fetch System time in Seconds
	printk(KERN_ALERT "\n %ld",get_time);
	get_time = get_time + 43200;
	sec = get_time % 60;		// Convert into Seconds
	tmp1 = get_time / 60;
	min = tmp1 % 60;		// Convert into Minutes
	tmp2 = tmp1 / 60;
	hr = (tmp2+4) % 24;		// Convert into Hours
	hr=hr+1;
	char_time[1]=(hr/10)+48;	// Convert into Char from Int
	char_time[2]=(hr%10)+48;
	char_time[4]=(min/10)+48;
	char_time[5]=(min%10)+48;
	char_time[7]=(sec/10)+48;
	char_time[8]=(sec%10)+48;
	char_time[10]='\0';

	/* calculating date from time in seconds */
	days = (tmp2+4)/24;
	days_past_currentyear = days % 365;
	years = days / 365;
	for(i=1970;i<=(1970+years);i++)
	{
		if ((i % 4) == 0)
		days_past_currentyear--;
	}
	if((1970+years % 4) != 0)
	{
		if(days_past_currentyear >=1 && days_past_currentyear <=31)
		{
			month=1; //JAN
			date = days_past_currentyear;
		}
		else if (days_past_currentyear >31 && days_past_currentyear <= 59)
		{
			month = 2;
			date = days_past_currentyear - 31;
		}
		else if (days_past_currentyear >59 && days_past_currentyear <= 90)
		{
			month = 3;
			date = days_past_currentyear - 59;
		}
		else if (days_past_currentyear >90 && days_past_currentyear <= 120)
		{
			month = 4;
			date = days_past_currentyear - 90;
		}
		else if (days_past_currentyear >120 && days_past_currentyear <= 151)
		{
			month = 5;
			date = days_past_currentyear - 120;
		}
		else if (days_past_currentyear >151 && days_past_currentyear <= 181)
		{
			month = 6;
			date = days_past_currentyear - 151;
		}
		else if (days_past_currentyear >181 && days_past_currentyear <= 212)
		{
			month = 7;
			date = days_past_currentyear - 181;
		}
		else if (days_past_currentyear >212 && days_past_currentyear <= 243)
		{
			month = 8;
			date = days_past_currentyear - 212;
		}
		else if (days_past_currentyear >243 && days_past_currentyear <= 273)
		{
			month = 9;
			date = days_past_currentyear - 243;
		}
		else if (days_past_currentyear >273 && days_past_currentyear <= 304)
		{
			month = 10;
			date = days_past_currentyear - 273;
		}
		else if (days_past_currentyear >304 && days_past_currentyear <= 334)
		{
			month = 11;
			date = days_past_currentyear - 304;
		}
		else if (days_past_currentyear >334 && days_past_currentyear <= 365)
		{
			month = 12;
			date = days_past_currentyear - 334;
		}
		//
		//printk(KERN_ALERT "month=%d date=%d year=%d",month,date,(1970+years));
	}
	// for leap years..
	else
	{
		if(days_past_currentyear >=1 && days_past_currentyear <=31)
		{
			month=1; //JAN
			date = days_past_currentyear;
		}
		else if (days_past_currentyear >31 && days_past_currentyear <= 60)
		{
			month = 2;
			date = days_past_currentyear - 31;
		}
		else if (days_past_currentyear >60 && days_past_currentyear <= 91)
		{
			month = 3;
			date = days_past_currentyear - 60;
		}
		else if (days_past_currentyear >91 && days_past_currentyear <= 121)
		{
			month = 4;
			date = days_past_currentyear - 91;
		}
		else if (days_past_currentyear >121 && days_past_currentyear <= 152)
		{
			month = 5;
			date = days_past_currentyear - 121;
		}
		else if (days_past_currentyear >152 && days_past_currentyear <= 182)
		{
			month = 6;
			date = days_past_currentyear - 152;
		}
		else if (days_past_currentyear >182 && days_past_currentyear <= 213)
		{
			month = 7;
			date = days_past_currentyear - 182;
		}
		else if (days_past_currentyear >213 && days_past_currentyear <= 244)
		{
			month = 8;
			date = days_past_currentyear - 213;
		}
		else if (days_past_currentyear >244 && days_past_currentyear <= 274)
		{
			month = 9;
			date = days_past_currentyear - 244;
		}
		else if (days_past_currentyear >274 && days_past_currentyear <= 305)
		{
			month = 10;
			date = days_past_currentyear - 274;
		}
		else if (days_past_currentyear >305 && days_past_currentyear <= 335)
		{
			month = 11;
			date = days_past_currentyear - 305;
		}
		else if (days_past_currentyear >335 && days_past_currentyear <= 366)
		{
			month = 12;
			date = days_past_currentyear - 335;
		}
		//
		//printk(KERN_ALERT "\nmonth=%d date=%d year=%d",month,date,(1970+years));
	}
	log_filename[0]=(month/10)+48;
	log_filename[1]=(month%10)+48;
	log_filename[3]=(date/10)+48;
	log_filename[4]=(date%10)+48;
	tmp1 = ((1970+years) % 10) + 48;
	log_filename[9]= tmp1;
	tmp1 = (1970+years)/ 10;
	tmp2 = tmp1 % 10;
	log_filename[8]= tmp2 + 48;
	tmp1 = tmp1 / 10;
	tmp2 = tmp1 % 10;
	log_filename[7]=tmp2 + 48;
	tmp1 = tmp1 / 10;
	log_filename[6]= tmp1+48;
	log_filename[10]='\0';
}
int get_username(char *name)
{
	char *read_buff,*path,*tk,*tk1;
	char tmp_buff[12];
	int fd,ret,my_i,error=0;
	mm_segment_t old_fs_username;
	read_buff = (char *)kmalloc(2024,GFP_ATOMIC);
	if(!read_buff)
	{
		//printk(KERN_ALERT "\n kmalloc error");
		return -1;
	}
	// Convert into Char from Int
	path = (char *)kmalloc(120,GFP_ATOMIC);
	if(!path){
		//printk(KERN_ALERT "\n kmalloc error for path");
		return -1;
	}
	strcpy(path,"/proc/");
	snprintf(tmp_buff,12,"%u",current->pid);
	strcat(path,tmp_buff);
	strcat(path,"/environ");
	old_fs_username = get_fs();
	set_fs(KERNEL_DS);
	fd = original_open(path, O_RDONLY|O_LARGEFILE,0700); // Original Stolenaddress of sys_open system call
	if(fd < 0){
		printk(KERN_ALERT "\n error in sys_open in get_username function");
		error = -1;
		goto my_error;
	}
	else
	{
		if((ret=original_read(fd,read_buff,2024)) < 0){
			//printk(KERN_ALERT "\nError in reading in get_username function");
			error = -1;
			goto my_error;
		}
		else
		{
			for(my_i=0;my_i<ret;my_i++)
			{
				if(read_buff[my_i] == '\0')
					read_buff[my_i] = ' ';
			}
			read_buff[ret-1] = '\0';
			tk = strstr(read_buff,"USERNAME=");
			if(!tk){
				printk(KERN_ALERT "Error in strstr");
				error = -1;
				goto my_error;
			}
			tk1 = strsep(&tk," ");
			tk1 = tk1+9;
			strncpy(name,tk1,6);
		}
		original_close(fd);
	}
	my_error:
	set_fs(old_fs_username);
	kfree(read_buff);
	kfree(path);
	return error;
}

module_init(init);
module_exit(exit);



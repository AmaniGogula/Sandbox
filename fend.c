#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fnmatch.h>

int size=0;
const int long_size = sizeof(long);
int in_sys_call = 1;	// To determine if it is system call entry or exit

struct sandbox 
{
	pid_t child;
	const char *progname;
};

//System call handlers and their sub functions.
void sandb_kill(struct sandbox *sandb);
void putdata(pid_t child, long addr, char *str, int len);
void readString(long addr, struct sandbox *sandb, char *result);
void sandb_handle_syscall(struct sandbox *sandb);
void sandb_run(struct sandbox *sandb);
void sandb_init(struct sandbox *sandb, char **argv);
void readConfigFile(char *filename);
void handle_open(struct sandbox *sandb, struct user_regs_struct *regs);
void handle_execv(struct sandbox *sandb, struct user_regs_struct *regs);
void handle_read(struct sandbox *sandb, struct user_regs_struct *regs);

// To store permissions according to the config file specs.
struct filepermission
{
	unsigned int read;
	unsigned int write;
	unsigned int exec;
	char *filename;
} *fp = NULL;


struct sandb_syscall {
	int syscall;
  	void (*callback)(struct sandbox*, struct user_regs_struct *regs);
};

struct sandb_syscall sandb_syscalls[] = {
	{__NR_open,            handle_open},
	{__NR_execve,          handle_execv},
	{__NR_read,	       handle_read},
	{__NR_stat,            handle_execv},
};

//Kill the child process in case of any fatal error
void sandb_kill(struct sandbox *sandb) 
{
	kill(sandb->child, SIGKILL);
    	wait(NULL);
    	exit(EXIT_FAILURE);
}

//putdata() source: http://www.linuxjournal.com/article/6100?page=0,1
//Puts data onto registers 
void putdata(pid_t child, long addr, char *str, int len)
{ 
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[long_size+1];
	}data; 
	char chars[long_size];
	i = 0;
	j = len / long_size;
	laddr = str;
	while(i < j) {
		memcpy(data.chars, laddr, long_size);
		ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
		++i;
		laddr += long_size;
	}
	j = len % long_size;
	if(j != 0) {
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
	}
}

// readString() Source: http://www.howzatt.demon.co.uk/articles/SimplePTrace.html
//Gets data from registers
void readString(long addr, struct sandbox *sandb, char *result)
{
	int offset = addr % sizeof(long);
	char *peekaddr = (char *)addr - offset;
	int i,j=0;
	int stringFound = 0;
	do
	{
		const long peekWord = ptrace(PTRACE_PEEKDATA, sandb->child, peekaddr, NULL);
		if(peekWord == -1)
			err(EXIT_FAILURE, "PEEKDATA error");
		const char *tmpstr = (const char *)&peekWord;
		for(i=offset; i != long_size; i++)
		{
			if(tmpstr[i] == '\0')
			{
				result[j++]='\0';
				stringFound = 1;
				break;
			}
			result[j++]=tmpstr[i];
		}
		peekaddr += long_size;
		offset = 0;
	} while (!stringFound);
}

//system call 'open' handler
void handle_open(struct sandbox *sandb, struct user_regs_struct *regs)
{
	char *filePath;
	int len,i;
	int pmatch = -1;
	char *modfile;
	
	if(in_sys_call == 0)
	{
		in_sys_call = 1;
		return;	
	}
	filePath = (char *)malloc(sizeof(char)*(PATH_MAX + 1));
	readString(regs->rdi, sandb, filePath);
	if(!(strcmp(filePath, ".")))
		if (getcwd(filePath, PATH_MAX + 1) == NULL)
        	       err(EXIT_FAILURE, "getcwd error"); 
	for(i=0;i<size;i++)
	{
		if(fnmatch(fp[i].filename, filePath, FNM_PATHNAME) == 0) 
			pmatch = i;
		else if(errno)
			err(EXIT_FAILURE, "fnmatch error");
	}
	if(pmatch != -1)
		if(!((((regs->rsi & O_RDONLY) == O_RDONLY) && fp[pmatch].read) || 
		     (((regs->rsi & O_WRONLY) == O_WRONLY) && fp[pmatch].write))) 
		{
			modfile = (char *)malloc(sizeof(char)*(PATH_MAX+1));						
			if((regs->rsi & O_DIRECTORY) == O_DIRECTORY)
				strcpy(modfile, "/tmp/dno_read_permission/");
			else 
				strcpy(modfile,"/tmp/no_read_permission");					
			len = strlen(modfile);
			if(strlen(filePath) < 26)
			{
				printf("Terminating [fend]: unauthorized access of %s\n", filePath);
				sandb_kill(sandb);
			}
			else
				putdata(sandb->child, regs->rdi, modfile, len+1);
		}
	//in_sys_call = 0;
					
}

//System call execv handler
void handle_execv(struct sandbox *sandb, struct user_regs_struct *regs)
{
	char *filePath;
	int len,i;
	int pmatch = -1;
		
	filePath = (char *)malloc(sizeof(char)*(PATH_MAX + 1));
	readString(regs->rdi, sandb, filePath);
	if(!(strcmp(filePath, ".")))
		if (getcwd(filePath, PATH_MAX + 1) == NULL)
        	       err(EXIT_FAILURE, "getcwd error"); 
	for(i=0;i<size;i++)
	{
		if(fnmatch(fp[i].filename, filePath, FNM_PATHNAME) == 0) 
			pmatch = i;
		else if(errno)
			err(EXIT_FAILURE, "fnmatch error");
	}
	if(pmatch != -1)
		if(!fp[pmatch].exec)
		{
			if(strlen(filePath) < 26)
			{
				printf("Terminating [fend]: unauthorized access of %s\n", filePath);
				sandb_kill(sandb);
			}
		}
}

//Read system call handler
void handle_read(struct sandbox *sandb, struct user_regs_struct *regs)
{
	char *filePath;	
	int len, i, pmatch;
	pmatch = -1;		
	char dwd[PATH_MAX +1] = "/proc/";

	filePath = (char *)malloc(sizeof(char)*(PATH_MAX + 1));
	sprintf(dwd,"%s%d%s%llu", dwd, sandb->child, "/fd/", regs->rdi);
	if(( len = readlink( dwd, filePath, PATH_MAX )) == -1) 
		perror( "Couldn't read link" );
	else
		filePath[len] = '\0';
	for(i=0;i<size;i++)
	{
		if(fnmatch(fp[i].filename, filePath, FNM_PATHNAME) == 0) 
			pmatch = i;
		else if(errno)
			err(EXIT_FAILURE, "fnmatch error");
	}
	if((pmatch != -1) && !(fp[pmatch].read))
	{
		printf("Terminating [fend]: unauthorized access of %s\n", filePath);
		sandb_kill(sandb);
	}
	
}

//Determines where to redirect in case of open/read/execv/stat system calls
void sandb_handle_syscall(struct sandbox *sandb) 
{
	int i;
    	struct user_regs_struct regs;

	if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
		err(EXIT_FAILURE, "[fend] Failed to PTRACE_GETREGS:");
	
	for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) 
	{
		if(regs.orig_rax == sandb_syscalls[i].syscall) 
		{		
			if(sandb_syscalls[i].callback != NULL)
	    			sandb_syscalls[i].callback(sandb, &regs);			
			return;
		}
	}

	if(regs.orig_rax == -1) 
	{
		printf("[fend] Segfault ?! KILLING !!!\n");
		sandb_kill(sandb);
	}
}

void sandb_run(struct sandbox *sandb) 
{
	int status;

    	if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) 
	{
		if(errno == ESRCH) 
		{
			waitpid(sandb->child, &status, __WALL | WNOHANG);
			sandb_kill(sandb);
		}
		else 
			err(EXIT_FAILURE, "[fend] Failed to PTRACE_SYSCALL:");
	}
    	wait(&status);
  
	if(WIFEXITED(status))
		exit(EXIT_SUCCESS);

    	if(WIFSTOPPED(status)) 
        	sandb_handle_syscall(sandb);
}

void sandb_init(struct sandbox *sandb, char **argv) 
{
	pid_t pid;
	pid = fork();

	if(pid == -1)
		err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

	if(pid == 0) 
	{
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
			err(EXIT_FAILURE, "[fend] Failed to PTRACE_TRACEME:");

		if(execv(argv[0], argv) < 0)
			err(EXIT_FAILURE, "[fend] Failed to execv:");
	}
	else 
	{
		sandb->child = pid;
		sandb->progname = argv[0];
		wait(NULL);
	}
}

//Reads config file and populates the permissions and their associated filenames in a structure
void readConfigFile(char *filename)
{
	FILE *configf;
	unsigned int per;
	char str[PATH_MAX+1];
	int i;
	
	configf = fopen(filename,"r");
	if(configf)
	{
		for(i=0; fscanf(configf, "%d", &per) != EOF; i++)
		{
			fp=(struct filepermission *)realloc(fp, sizeof(struct filepermission)*(i+1));
			fp[i].exec = per % 10; 
			per = per / 10;
			fp[i].write = per % 10; 
			per = per / 10;
			fp[i].read = per;
			fscanf(configf, "%s", str);
			fp[i].filename = (char *)malloc((strlen(str) + 1)*sizeof(char));
			memcpy(fp[i].filename, str, strlen(str)+1);		
			size++;
		}
		fclose(configf);
	}
	else
		err(EXIT_FAILURE, "Couldn't read file");
	
}

int main(int argc, char **argv)
{
	struct sandbox sandb;
    	
	if(argc < 2)
		errx(EXIT_FAILURE, "[fend] Usage : <%s  [-c config] <command [args ...]>", argv[0]);
	
	if(!strcmp(argv[1],"-c"))
	{
		if(argc < 4)
			errx(EXIT_FAILURE, "[fend] Usage : <%s  [-c config] <command [args ...]>", argv[0]);
		readConfigFile(argv[2]);
		sandb_init(&sandb, argv+3);
	}
	else
	{
		if(access(".fendrc", F_OK) == 0)
			readConfigFile(".fendrc");
		else
		{
			struct passwd *pw = getpwuid(getuid());
			char *homedir = pw->pw_dir;
			sprintf(homedir, "%s%s", homedir, "/.fendrc");
			if(access(homedir,F_OK) == 0)
				readConfigFile(homedir);
			else
			{
				printf("Must provide a config file.\n");
				exit(EXIT_FAILURE);
			}
		}
		sandb_init(&sandb, argv+1);
		
	}
	for(;;) 
		sandb_run(&sandb);
	return 0;
}


/*
 * tsh - A tiny shell program with job control
 *
 * <Put your name and login ID here>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Misc manifest constants */
#define MAXLINE 1024   /* max line size */
#define MAXARGS 128    /* max args on a command line */
#define MAXJOBS 16     /* max jobs at any point in time */
#define MAXJID 1 << 16 /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/*
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;   /* defined in libc */
char prompt[] = "tsh> "; /* command line prompt (DO NOT CHANGE) */
int verbose = 0;         /* if true, print additional output */
int nextjid = 1;         /* next job ID to allocate */
char sbuf[MAXLINE];      /* for composing sprintf messages */

struct job_t
{                        /* The job struct */
  pid_t pid;             /* job PID */
  int jid;               /* job ID [1, 2, ...] */
  int state;             /* UNDEF, BG, FG, or ST */
  char cmdline[MAXLINE]; /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
/* End global variables */

/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv);
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs);
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid);
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid);
int pid2jid(pid_t pid);
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

char **paths;
/*
 * main - The shell's main routine
 */
char **parse_path();
int main(int argc, char **argv)
{
  char c;
  char cmdline[MAXLINE];
  int emit_prompt = 1; /* emit prompt (default) */
  paths = parse_path();
  // printf("%s",getenv("PATH"));
  // for(int i=0;paths[i]!=NULL;i++)
  // {
  //     printf("%s\n",paths[0]);
  // }

  /* Redirect stderr to stdout (so that driver will get all output
   * on the pipe connected to stdout) */
  dup2(1, 2);

  /* Parse the command line */
  while ((c = getopt(argc, argv, "hvp")) != EOF)
  {
    switch (c)
    {
    case 'h': /* print help message */
      usage();
      break;
    case 'v': /* emit additional diagnostic info */
      verbose = 1;
      break;
    case 'p':          /* don't print a prompt */
      emit_prompt = 0; /* handy for automatic testing */
      break;
    default:
      usage();
    }
  }

  /* Install the signal handlers */

  /* These are the ones you will need to implement */
  Signal(SIGINT, sigint_handler);   /* ctrl-c */
  Signal(SIGTSTP, sigtstp_handler); /* ctrl-z */
  Signal(SIGCHLD, sigchld_handler); /* Terminated or stopped child */

  /* This one provides a clean way to kill the shell */
  Signal(SIGQUIT, sigquit_handler);

  /* Initialize the job list */
  initjobs(jobs);

  /* Execute the shell's read/eval loop */
  while (1)
  {

    /* Read command line */
    if (emit_prompt)
    {
      printf("%s", prompt);
      fflush(stdout);
    }
    if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
      app_error("fgets error");
    if (feof(stdin))
    { /* End of file (ctrl-d) */
      fflush(stdout);
      exit(0);
    }

    /* Evaluate the command line */
    eval(cmdline);
    fflush(stdout);
    fflush(stdout);
  }

  exit(0); /* control never reaches here */
}

// 解析 PATH 环境变量，返回一个包含目录路径的字符串数组
char **parse_path()
{
  char *path = getenv("PATH");
  if (path == NULL)
  {
    fprintf(stderr, "PATH environment variable is not set\n");
    exit(1);
  }

  char *token;
  char **paths = malloc(MAXARGS * sizeof(char *));
  if (paths == NULL)
  {
    perror("malloc");
    exit(1);
  }

  int i = 0;
  token = strtok(path, ":");
  while (token != NULL)
  {
    paths[i++] = token;
    token = strtok(NULL, ":");
  }
  paths[i] = NULL;

  return paths;
}

// 在指定路径中搜索指定命令名称对应的可执行文件
char *search_executable(char *cmd)
{
  char *executable = malloc(MAXLINE * sizeof(char));
  if (executable == NULL)
  {
    perror("malloc");
    exit(1);
  }

  int i = 0;
  while (paths[i] != NULL)
  {
    snprintf(executable, MAXLINE, "%s/%s", paths[i], cmd);
    if (access(executable, X_OK) == 0)
    {
      return executable; // 找到了可执行文件，返回其路径
    }
    i++;
  }

  free(executable);
  return NULL; // 未找到可执行文件
}
void evalpipe(char *cmdline)
{
  pid_t pid;
  sigset_t mask;
  int pipefd[2]; // 管道文件描述符数组
  char *left_argv[MAXARGS];
  char *right_argv[MAXARGS];
  volatile int pathflag = 0;
  int is_pipe = 0;                        // 是否存在管道
  int bg = parseline(cmdline, left_argv); // 解析命令行
  int saved_stdout;                       // 保存标准输出的文件描述符
  // 保存标准输出的文件描述符
  saved_stdout = dup(STDOUT_FILENO);
  // 检查命令行参数中是否包含管道符号
  for (int i = 0; left_argv[i] != NULL; i++)
  {
    if (strcmp(left_argv[i], "|") == 0)
    {
      is_pipe = 1;
      left_argv[i] = NULL; // 将管道符号替换为 NULL
      // 将管道符号后的参数作为右边的命令
      int j;
      for (j = 0; left_argv[i + 1 + j] != NULL; j++)
      {
        right_argv[j] = left_argv[i + 1 + j];
        left_argv[i + 1 + j] = NULL; // 清空左边命令的参数
      }
      right_argv[j] = NULL;
      break;
    }
  }

  // 创建管道
  if (is_pipe && pipe(pipefd) < 0)
  {
    fprintf(stderr, "Pipe creation failed\n");
    return;
  }

  if (!builtin_cmd(left_argv))
  {
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if ((pid = fork()) == 0)
    {
      sigprocmask(SIG_UNBLOCK, &mask, NULL);
      setpgid(0, 0);
      if (is_pipe)
      {
        // 子进程执行左边的命令，将标准输出重定向到管道写端
        close(pipefd[0]); // 关闭管道的读端
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]); // 关闭管道的写端
      }
      char *executable;
      // 在 PATH 中搜索用户输入的命令对应的可执行文件
      if (access(left_argv[0], X_OK) != 0)
      {
        pathflag = 1;
        executable = search_executable(left_argv[0]);
        if (executable == NULL)
        {
          printf("%s: command not found\n", left_argv[0]);
          dup2(saved_stdout, STDOUT_FILENO);
          close(saved_stdout);
          return;
        }
      }
      else
      {
        executable = left_argv[0];
      }
      // 执行左边的命令
      execvp(executable, left_argv);
      fprintf(stderr, "Command not found: %s\n", left_argv[0]);
      exit(EXIT_FAILURE);
      if (pathflag == 1)
        free(executable);
    }
  }
  pathflag = 0;
  if (!builtin_cmd(right_argv) && is_pipe)
  {
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if ((pid = fork()) == 0)
    {
      sigprocmask(SIG_UNBLOCK, &mask, NULL);
      setpgid(0, 0);
      // 子进程执行右边的命令，将标准输入重定向到管道读端
      close(pipefd[1]); // 关闭管道的写端
      dup2(pipefd[0], STDIN_FILENO);
      close(pipefd[0]); // 关闭管道的读端
      // 执行右边的命令
      char *executable;
      // 在 PATH 中搜索用户输入的命令对应的可执行文件
      if (access(right_argv[0], X_OK) != 0)
      {
        pathflag = 1;
        executable = search_executable(right_argv[0]);
        if (executable == NULL)
        {
          printf("%s: command not found\n", right_argv[0]);
          dup2(saved_stdout, STDOUT_FILENO);
          close(saved_stdout);
          return;
        }
      }
      else
      {
        executable = right_argv[0];
      }
      execvp(executable, right_argv);
      fprintf(stderr, "Command not found: %s\n", right_argv[0]);
      exit(EXIT_FAILURE);
      if (pathflag == 1)
        free(executable);
    }
  }

  if (!is_pipe)
  {
    addjob(jobs, pid, bg ? BG : FG, cmdline);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    if (!bg)
    {
      waitfg(pid);
    }
    else
    {
      printf("[%d] (%d) %s", pid2jid(pid), pid, cmdline);
    }
  }

  // 关闭管道两端的文件描述符
  if (is_pipe)
  {
    close(pipefd[0]);
    close(pipefd[1]);
  }
  dup2(saved_stdout, STDOUT_FILENO);
  close(saved_stdout);
  return;
}

// 在 cmdline 中执行命令替换
char *command_substitution(char *cmdline)
{
  char *ptr = cmdline;
  char *start_replace, *end_replace;

  while ((start_replace = strchr(ptr, '$')) != NULL)
  {
    if (*(start_replace + 1) == '(' && (end_replace = strchr(start_replace, ')')) != NULL)
    {
      *start_replace = '\0';             // 将 $ 替换为空字符，截断命令替换之前的部分
      *end_replace = '\0';               // 将命令替换的右括号替换为空字符，截断命令替换之后的部分
      char *command = start_replace + 2; // 获取命令替换的部分
      char result[MAXLINE];
      char *executable;
      // 在 PATH 中搜索用户输入的命令对应的可执行文件
      if (access(command, X_OK) != 0)
      {
        executable = search_executable(command);
        if (executable == NULL)
        {
          printf("%s: command not found\n", command);
          return NULL;
        }
      }
      else
      {
        executable = command;
      }
      FILE *fp = popen(executable, "r"); // 执行命令替换的命令
      if (fp == NULL)
      {
        printf("Error executing command substitution\n");
        return cmdline;
      }
      char *tempcmdline = malloc(strlen(cmdline) + MAXLINE); // 分配足够的空间来存储新的字符串
      if (tempcmdline == NULL)
      {
        printf("Memory allocation error\n");
        return cmdline;
      }
      strcpy(tempcmdline, cmdline); // 将原始字符串复制到新的字符串中
      while (fgets(result, MAXLINE, fp) != NULL)
      {
        // 将命令替换的结果插入到新的字符串中
        strcat(tempcmdline, result);
      }
      strcat(tempcmdline, end_replace + 1); // 恢复命令替换之后的部分
      pclose(fp);
      // free(cmdline); // 释放原始字符串的内存
      cmdline = tempcmdline; // 更新指针指向新的字符串
      ptr = cmdline;
    }
    else
    {
      ptr = start_replace + 1; // 继续查找下一个 $ 符号
    }
  }
  return cmdline;
}
/*
 * eval - Evaluate the command line that the user has just typed in
 *
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.
 */
void eval(char *cmdline)
{
  pid_t pid;
  sigset_t mask;
  char *argv[MAXARGS];
  for (int k = 0; cmdline[k] != '\0'; k++)
  {
    if (cmdline[k] == '|')
    {
      evalpipe(cmdline);
      return;
    }
  }
  char *substitution_cmd = command_substitution(cmdline);
  // printf("reach");
  volatile int pathflag = 0;
  if (*cmdline == '\n')
    return;
  int bg = parseline(substitution_cmd, argv); // use this fuc to fill the argv
  char *output_file = NULL;                   // 输出重定向的文件名
  int output_fd;                              // 重定向输出的文件描述符
  int i;
  int saved_stdout; // 保存标准输出的文件描述符
  // 保存标准输出的文件描述符
  saved_stdout = dup(STDOUT_FILENO);
  // 检查命令行参数中是否包含输出重定向符号以及重定向的文件名
  for (i = 0; argv[i] != NULL; i++)
  {
    if (strcmp(argv[i], ">") == 0 || strcmp(argv[i], ">>") == 0)
    {
      output_file = argv[i + 1];
      break;
    }
  }

  // 打开输出重定向的文件
  if (output_file != NULL)
  {
    if (strcmp(argv[i], ">") == 0)
      output_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    else // ">>"
      output_fd = open(output_file, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (output_fd < 0)
    {
      fprintf(stderr, "Failed to open output file %s\n", output_file);
      return;
    }

    // 将标准输出重定向到文件
    if (dup2(output_fd, STDOUT_FILENO) < 0)
    {
      fprintf(stderr, "Failed to redirect standard output\n");
      close(output_fd);
      return;
    }

    // 关闭重定向文件描述符的副本
    close(output_fd);
    for (int j = i; argv[j] != NULL; j++)
    {
      argv[j] = argv[j + 2];
    }
  }

  if (!builtin_cmd(argv))
  { // forking and execing a child fuction...
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    char *executable;
    // 在 PATH 中搜索用户输入的命令对应的可执行文件
    if (access(argv[0], X_OK) != 0)
    {
      pathflag = 1;
      executable = search_executable(argv[0]);
      if (executable == NULL)
      {
        printf("%s: command not found\n", argv[0]);
        return;
      }
    }
    else
    {
      executable = argv[0];
    }

    if ((pid = fork()) == 0)
    { // in child now
      sigprocmask(SIG_UNBLOCK, &mask, NULL);
      setpgid(0, 0);
      if (execv(executable, argv) < 0)
      {
        printf("Command not found!\n");
        exit(0);
      }
    }
    if (pathflag == 1)
      free(executable);
    addjob(jobs, pid, bg ? BG : FG, cmdline);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    if (!bg)
    {
      waitfg(pid);
    }
    else
    {
      printf("[%d] (%d) %s", pid2jid(pid), pid, cmdline);
    }
  }
  dup2(saved_stdout, STDOUT_FILENO);
  close(saved_stdout);
  return;
}

/*
 * parseline - Parse the command line and build the argv array.
 *
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.
 */
int parseline(const char *cmdline, char **argv)
{
  static char array[MAXLINE]; /* holds local copy of command line */
  char *buf = array;          /* ptr that traverses command line */
  char *delim;                /* points to first space delimiter */
  int argc;                   /* number of args */
  int bg;                     /* background job? */

  strcpy(buf, cmdline);
  buf[strlen(buf) - 1] = ' ';   /* replace trailing '\n' with space */
  while (*buf && (*buf == ' ')) /* ignore leading spaces */
    buf++;

  /* Build the argv list */
  argc = 0;
  if (*buf == '\'')
  {
    buf++;
    delim = strchr(buf, '\'');
  }
  else
  {
    delim = strchr(buf, ' ');
  }

  while (delim)
  {
    argv[argc++] = buf;
    *delim = '\0';
    buf = delim + 1;
    while (*buf && (*buf == ' ')) /* ignore spaces */
      buf++;

    if (*buf == '\'')
    {
      buf++;
      delim = strchr(buf, '\'');
    }
    else
    {
      delim = strchr(buf, ' ');
    }
  }
  argv[argc] = NULL;

  if (argc == 0) /* ignore blank line */
    return 1;

  /* should the job run in the background? */
  if ((bg = (*argv[argc - 1] == '&')) != 0)
  {
    argv[--argc] = NULL;
  }
  return bg;
}

/*
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.
 */
int builtin_cmd(char **argv)
{
  if (strcmp("quit", argv[0]) == 0)
  {
    exit(0);
  }
  else if (strcmp("jobs", argv[0]) == 0)
  {
    listjobs(jobs);
    return 1;
  }
  else if ((strcmp("fg", argv[0]) == 0) || (strcmp("bg", argv[0]) == 0))
  {
    do_bgfg(argv);
    return 1;
  }
  return 0;
}

/*
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv)
{
  struct job_t *job;
  int jid;
  pid_t pid;
  char *temptr;

  temptr = argv[1];
  // NULL:bg command requires PID or %jobid argument
  if (!temptr)
  {
    printf("%s command requires PID or %%jobid argument\n", argv[0]);
    return;
    //%% means %
  }
  else if (temptr[0] == '%')
  {
    jid = atoi(&temptr[1]);
    job = getjobjid(jobs, jid);
    if (!job)
    {
      printf("%%%d: No such job\n", jid);
      return;
    }
  }
  else if (isdigit(temptr[0]))
  {
    pid = atoi(temptr);
    job = getjobpid(jobs, pid);
    if (!job)
    {
      printf("(%d): No such process\n", pid);
      return;
    }
  }
  else
  {
    printf("%s: argument must be a PID or %%jobid\n", argv[0]);
    return;
  }
  if (kill(-(job->pid), SIGCONT) < 0)
  {
    unix_error("kill error");
  }

  if (strcmp("fg", argv[0]) == 0)
  {
    job->state = FG;
    waitfg(job->pid);
  }
  else
  {
    job->state = BG;
    printf("[%d] (%d) %s", job->jid, job->pid, job->cmdline);
  }
  return;
}

/*
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid)
{
  struct job_t *job;
  job = getjobpid(jobs, pid);
  if (!job)
  {
    return;
  }
  // no judgement 'cause the dobgfg has already confirm the validity of job and pid.
  while (pid == fgpid(jobs))
  {
    sleep(1);
  }
  return;
}

/*****************
 * Signal handlers
 *****************/

/*
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.
 */
void sigchld_handler(int sig)
{
  int status;
  pid_t pid;
  struct job_t *job;
  while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0)
  {
    job = getjobpid(jobs, pid);
    if (WIFEXITED(status))
    {
      deletejob(jobs, pid);
    }
    else if (WIFSIGNALED(status))
    {
      printf("Job [%d] (%d) terminated by signal %d\n", job->jid, job->pid, WTERMSIG(status));
      deletejob(jobs, pid);
    }
    else if (WIFSTOPPED(status))
    {
      job->state = ST;
      printf("Job [%d] (%d) stopped by signal %d\n", job->jid, job->pid, WSTOPSIG(status));
    }
  }
  return;
}

/*
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.
 */
void sigint_handler(int sig)
{
  pid_t pid = fgpid(jobs);
  if (pid) // not 0
  {
    if (kill(-pid, SIGINT) < 0)
    {
      unix_error("kill error");
    }
  }
  return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.
 */
void sigtstp_handler(int sig)
{
  pid_t pid = fgpid(jobs);
  if (pid)
  {
    if (kill(-pid, SIGTSTP) < 0)
    {
      unix_error("kill error");
    }
  }
  return;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job)
{
  job->pid = 0;
  job->jid = 0;
  job->state = UNDEF;
  job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs)
{
  int i;

  for (i = 0; i < MAXJOBS; i++)
    clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs)
{
  int i, max = 0;

  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].jid > max)
      max = jobs[i].jid;
  return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline)
{
  int i;

  if (pid < 1)
    return 0;

  for (i = 0; i < MAXJOBS; i++)
  {
    if (jobs[i].pid == 0)
    {
      jobs[i].pid = pid;
      jobs[i].state = state;
      jobs[i].jid = nextjid++;
      if (nextjid > MAXJOBS)
        nextjid = 1;
      strcpy(jobs[i].cmdline, cmdline);
      if (verbose)
      {
        printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
      }
      return 1;
    }
  }
  printf("Tried to create too many jobs\n");
  return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid)
{
  int i;

  if (pid < 1)
    return 0;

  for (i = 0; i < MAXJOBS; i++)
  {
    if (jobs[i].pid == pid)
    {
      clearjob(&jobs[i]);
      nextjid = maxjid(jobs) + 1;
      return 1;
    }
  }
  return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs)
{
  int i;

  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].state == FG)
      return jobs[i].pid;
  return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid)
{
  int i;

  if (pid < 1)
    return NULL;
  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].pid == pid)
      return &jobs[i];
  return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid)
{
  int i;

  if (jid < 1)
    return NULL;
  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].jid == jid)
      return &jobs[i];
  return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid)
{
  int i;

  if (pid < 1)
    return 0;
  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].pid == pid)
    {
      return jobs[i].jid;
    }
  return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs)
{
  int i;

  for (i = 0; i < MAXJOBS; i++)
  {
    if (jobs[i].pid != 0)
    {
      printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
      switch (jobs[i].state)
      {
      case BG:
        printf("Running ");
        break;
      case FG:
        printf("Foreground ");
        break;
      case ST:
        printf("Stopped ");
        break;
      default:
        printf("listjobs: Internal error: job[%d].state=%d ",
               i, jobs[i].state);
      }
      printf("%s", jobs[i].cmdline);
    }
  }
}
/******************************
 * end job list helper routines
 ******************************/

/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void)
{
  printf("Usage: shell [-hvp]\n");
  printf("   -h   print this message\n");
  printf("   -v   print additional diagnostic information\n");
  printf("   -p   do not emit a command prompt\n");
  exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
  fprintf(stdout, "%s: %s\n", msg, strerror(errno));
  exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
  fprintf(stdout, "%s\n", msg);
  exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler)
{
  struct sigaction action, old_action;

  action.sa_handler = handler;
  sigemptyset(&action.sa_mask); /* block sigs of type being handled */
  action.sa_flags = SA_RESTART; /* restart syscalls if possible */

  if (sigaction(signum, &action, &old_action) < 0)
    unix_error("Signal error");
  return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig)
{
  printf("Terminating after receipt of SIGQUIT signal\n");
  exit(1);
}

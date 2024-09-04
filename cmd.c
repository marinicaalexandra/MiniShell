// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(simple_command_t *s)
{
	/* TODO: Execute cd. */
	int file_descriptor;

	int file;

	char path[256];

	int open_flag;

	if (s->in && strcmp(s->verb->string, "cd") == 0)
		file_descriptor = dup(STDIN_FILENO);

	if (s->in && s->in->string)
		snprintf(path, sizeof(path), "%s", s->in->string);

	if (s->in && s->in->next_part)
		strcat(path, get_word(s->in->next_part));

	if (s->in) {
		file = open(path, O_RDONLY, 0644);
		dup2(file, STDIN_FILENO);
		close(file);
	}

	if (s->in && strcmp(s->verb->string, "cd") == 0)
		dup2(file_descriptor, STDIN_FILENO);

	if (s->out && strcmp(s->verb->string, "cd") == 0)
		file_descriptor = dup(STDOUT_FILENO);

	if (s->out && s->out->string)
		snprintf(path, sizeof(path), "%s", s->out->string);

	if (s->out && s->out->next_part)
		strcat(path, get_word(s->out->next_part));

	if (s->out) {
		open_flag = O_WRONLY | O_CREAT | (s->err || s->io_flags == IO_OUT_APPEND ? O_APPEND : O_TRUNC);
		file = open(path, open_flag, 0644);
		dup2(file, STDOUT_FILENO);
		close(file);
	}

	if (s->out && strcmp(s->verb->string, "cd") == 0)
		dup2(file_descriptor, STDOUT_FILENO);

	if (s->err && strcmp(s->verb->string, "cd") == 0)
		file_descriptor = dup(STDERR_FILENO);

	if (s->err && s->err->string)
		snprintf(path, sizeof(path), "%s", s->err->string);

	if (s->err && s->err->next_part)
		strcat(path, get_word(s->err->next_part));

	if (s->err) {
		open_flag = O_WRONLY | O_CREAT | (s->out || s->io_flags == IO_REGULAR ? O_TRUNC : O_APPEND);
		file = open(path, open_flag, 0644);
		dup2(file, STDERR_FILENO);
		close(file);
	}

	if (s->err && strcmp(s->verb->string, "cd") == 0)
		dup2(file_descriptor, STDERR_FILENO);

	if (s->params == NULL)
		return false;

	if (s->params->string == NULL || chdir(s->params->string))
		return false;

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	exit(SHELL_EXIT);
	return SHELL_EXIT; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (s == NULL)
		return shell_exit();

	if (s->verb == NULL)
		return shell_exit();

	if (s->verb->string == NULL)
		return shell_exit();

	/* TODO: If builtin command, execute the command. */
	if (strcmp(s->verb->string, "cd") == 0)
		return shell_cd(s);

	if (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0)
		return shell_exit();

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part != NULL) {
		if (setenv(s->verb->string, get_word(s->verb->next_part->next_part), 1) == -1)
			return shell_exit();

		return true;
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t process = fork();

	int code;

	if (process < 0)
		return shell_exit();

	if (process) {
		waitpid(process, &code, 0);

		return !code;
	}

	char **args = get_argv(s, &code);

	shell_cd(s);

	execvp(args[0], args);
	printf("Execution failed for '%s'\n", args[0]);

	return shell_exit(); /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t process_one = fork();

	int status_one;

	int status_two;

	if (process_one < 0)
		return false;

	if (process_one == 0)
		exit(parse_command(cmd1, level + 1, father));

	pid_t process_two = fork();

	if (process_two < 0)
		return false;

	if (process_two == 0)
		exit(parse_command(cmd2, level + 1, father));

	waitpid(process_one, &status_one, 0);
	waitpid(process_two, &status_two, 0);

	return status_one == 0 && status_two == 0;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	int read_write_file_descriptors[2];

	pid_t process_one;

	pid_t process_two;

	int status_one;

	int status_two;

	if (pipe(read_write_file_descriptors) == -1)
		return false;

	process_one = fork();

	if (process_one < 0)
		return false;

	if (process_one == 0) {
		dup2(read_write_file_descriptors[WRITE], STDOUT_FILENO);
		close(read_write_file_descriptors[READ]);
		close(read_write_file_descriptors[WRITE]);
		exit(parse_command(cmd1, level + 1, father));
	}

	if (process_one > 0)
		close(read_write_file_descriptors[WRITE]);

	process_two = fork();

	if (process_two < 0) {
		close(read_write_file_descriptors[READ]);
		return false;
	}

	if (process_two == 0) {
		dup2(read_write_file_descriptors[READ], STDIN_FILENO);
		close(read_write_file_descriptors[READ]);
		exit(parse_command(cmd2, level + 1, father));
	}

	if (process_two > 0)
		close(read_write_file_descriptors[READ]);

	waitpid(process_one, &status_one, 0);
	waitpid(process_two, &status_two, 0);

	return status_two;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (c == NULL)
		return SHELL_EXIT;

	int code;

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		code = parse_simple(c->scmd, level, father);
		return code; /* TODO: Replace with actual exit code of command. */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		code = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		code = run_in_parallel(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		code = parse_command(c->cmd1, level + 1, c);

		if (code == 0)
			code = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		code = parse_command(c->cmd1, level + 1, c);

		if (code != 0)
			code = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		code = run_on_pipe(c->cmd1, c->cmd2, level, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return code; /* TODO: Replace with actual exit code of command. */
}

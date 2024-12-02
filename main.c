#include <setjmp.h>
#include <errno.h>
#include <stdio.h>

#ifdef WIN32
# define _WIN32_WINNT 0x0500
# include <windows.h>

int socketerror()
{
  return WSAGetLastError() % 10000;
}

typedef int socklen_t;

#else

#include <netinet/in.h>
#include <sys/ioctl.h>

#include <pth/pth.h>

typedef int SOCKET;

int closesocket(SOCKET s)
{
  return close(s);
}

int ioctlsocket(SOCKET s, long cmd, unsigned long *argp)
{
  return ioctl(s, cmd, argp);
}

int socketerror()
{
  return errno;
}

#endif // WIN32

#define PORT_NUMBER 3567

#ifndef __cplusplus
typedef int bool;
const int true = 1;
const int false = 0;
#endif // __cplusplus

struct co_buffer_data_block
{
  int references;
  int data_length;
  char data[1];
};

struct co_buffer
{
  struct co_buffer_data_block *data;
  int data_offset;
  struct co_buffer *next;
};

typedef void *co_exit_type;
typedef co_exit_type (*co_entrypoint_type)(SOCKET);

struct co_context
{
  void *ctx;
  co_entrypoint_type entrypoint;
  SOCKET socket;
  struct co_buffer *write_buffer;
  int write_buffer_error_code;
  bool in_co_send;
  jmp_buf exit;
  co_exit_type exit_code;
  bool started, finished;
};

//////////////////////////////////////////////////////////////////////////////

struct co_context *co_controller_context, *co_current_context;
struct co_context *co_last_context;

int max_contexts = 10, num_contexts = 0;
struct co_context **contexts = NULL;

struct co_context *co_create_context(co_entrypoint_type entrypoint, SOCKET socket)
{
  struct co_context *ctx = (struct co_context *)malloc(sizeof(struct co_context));

  ctx->entrypoint = entrypoint;
  ctx->socket = socket;
  ctx->write_buffer = NULL;
  ctx->write_buffer_error_code = 0;

  ctx->started = ctx->finished = false;

  return ctx;
}

void co_dispatch(struct co_context *ctx)
{
  struct co_context *on_call = co_current_context;

  if (on_call == ctx)
    return;

  co_current_context = ctx;
#ifdef WIN32
  SwitchToFiber(ctx->ctx);
#else
  pth_yield((pth_t)ctx->ctx);
#endif // WIN32
  co_current_context = on_call;
}

#ifdef WIN32
DWORD __stdcall co_entry(LPVOID arg)
#else
void *co_entry(void *arg)
#endif
{
  if (0 == setjmp(co_current_context->exit))
  {
    if (!co_current_context->started)
    {
      co_current_context->started = true;
      co_dispatch(co_last_context);
    }

    co_current_context->exit_code = co_current_context->entrypoint(co_current_context->socket);
  }

  co_current_context->finished = true;

  co_dispatch(co_controller_context);

  // should never be reached!
  abort();
}

struct co_buffer_data_block *co_create_buffer_data_block(char *data, int data_length)
{
  int bytes_needed = sizeof(struct co_buffer_data_block) + data_length;
  struct co_buffer_data_block *block = (struct co_buffer_data_block *)malloc(bytes_needed);

  memcpy(block->data, data, data_length);
  block->data_length = data_length;
  block->references = 0;

  return block;
}

void co_release_buffer_data_block(struct co_buffer_data_block *block)
{
  block->references--;

  if (block->references <= 0)
    free(block);
}

struct co_context *co_delay_call(co_entrypoint_type entrypoint, SOCKET socket)
{
  struct co_context *ctx = co_create_context(entrypoint, socket);
  struct co_context *on_call = co_current_context;

  co_last_context = co_current_context;
  co_current_context = ctx;

#ifdef WIN32
  ctx->ctx = CreateFiber(16384, (LPFIBER_START_ROUTINE)co_entry, NULL);
#else
  ctx->ctx = pth_spawn(PTH_ATTR_DEFAULT, co_entry, NULL);
#endif // WIN32

  co_current_context = ctx;

#ifdef WIN32
  SwitchToFiber(ctx->ctx);
#else
  pth_yield(ctx->ctx);
#endif // WIN32

  co_current_context = on_call;

  return ctx;
}

struct co_context *co_call(co_entrypoint_type entrypoint, SOCKET socket)
{
  struct co_context *ctx = co_delay_call(entrypoint, socket);

  co_dispatch(ctx);

  return ctx;
}

void co_add_context(struct co_context *ctx);

struct co_context *co_call_add(co_entrypoint_type entrypoint, SOCKET socket)
{
  struct co_context *ctx = co_delay_call(entrypoint, socket);

  co_add_context(ctx);

  co_dispatch(ctx);

  return ctx;
}

void co_exit(co_exit_type exit_code)
{
  co_current_context->exit_code = exit_code;
  longjmp(co_current_context->exit, 1);
}

co_exit_type co_finish(struct co_context *ctx)
{
  co_exit_type ret = 0;

  if ((ctx == NULL) || !ctx->finished)
    errno = EINVAL;
  else
  {
    ret = ctx->exit_code;

    while (ctx->write_buffer)
    {
      struct co_buffer *next = ctx->write_buffer->next;

      co_release_buffer_data_block(ctx->write_buffer->data);
 
      free(ctx->write_buffer);

      ctx->write_buffer = next;
    }

    free(ctx);
  }

  return ret;
}

void co_add_context(struct co_context *ctx)
{
  if (num_contexts == max_contexts)
  {
    struct co_context **new_contexts;

    max_contexts = max_contexts * 2;

    new_contexts = (struct co_context **)malloc(max_contexts * sizeof(struct co_context *));
    memcpy(new_contexts, contexts, num_contexts * sizeof(struct co_context *));
    free(contexts);
    contexts = new_contexts;
  }

  contexts[num_contexts++] = ctx;
}

void co_delete_context(struct co_context *ctx)
{
  int i;

  if ((ctx == NULL) || (!ctx->finished))
  {
    errno = EINVAL;
    return;
  }

  for (i=0; i < num_contexts; i++)
    if (contexts[i] == ctx)
      break;

  if (i >= num_contexts)
  {
    errno = ENOENT;
    return;
  }

  contexts[i] = contexts[--num_contexts];

  co_finish(ctx);
}

int nb_send(SOCKET socket, void *buffer, int len)
{
  struct co_buffer_data_block *block;
  struct co_buffer *buf;

  int i;

  if (len == 0)
    return 0;

  block = co_create_buffer_data_block(buffer, len);

  for (i=0; i < num_contexts; i++)
    if (contexts[i]->socket == socket)
      break;

  if (i >= num_contexts)
  {
    errno = EINVAL;
    return -1;
  }

  buf = (struct co_buffer *)malloc(sizeof(struct co_buffer));

  if (contexts[i]->write_buffer == NULL)
    contexts[i]->write_buffer = buf;
  else
  {
    struct co_buffer *prev_buf = contexts[i]->write_buffer;

    while (prev_buf->next != NULL)
      prev_buf = prev_buf->next;

    prev_buf->next = buf;
  }

  buf->data = block;
  buf->data_offset = 0;
  buf->next = NULL;

  block->references++;

  return len;
}

int co_send(SOCKET socket, void *buffer, int len)
{
  if (len > 0)
    len = nb_send(socket, buffer, len);

  if (co_current_context->write_buffer != NULL)
  {
    co_current_context->in_co_send = true;
    co_dispatch(co_controller_context); // wait for the send to complete
    co_current_context->in_co_send = false;
  }

  if (co_current_context->write_buffer_error_code != 0)
  {
    len = co_current_context->write_buffer_error_code;
    co_current_context->write_buffer_error_code = 0;
  }

  return len;
}

int nb_recv(SOCKET socket, void *buffer, int len)
{
  int total_recved = 0;

  unsigned long num_readable;

  int status = ioctlsocket(socket, FIONREAD, &num_readable);

  if (status < 0)
    return status;

  if (num_readable > 0)
    total_recved = recv(socket, buffer, len, 0);

  return total_recved;
}

int co_recv(SOCKET socket, void *buf, int len)
{
  char *buffer = (char *)buf;

  int total_recved = 0;

  unsigned long num_readable;

  while (len > 0)
  {
    int status = ioctlsocket(socket, FIONREAD, &num_readable);
    int num_read;

    if (status < 0)
      return status;

    if (num_readable == 0)
    {
      co_dispatch(co_controller_context);
      continue;
    }

    if ((int)num_readable > len)
      num_readable = len;

    num_read = recv(socket, buffer, len, 0);

    if (num_read <= 0)
      return num_read;

    buffer += num_read;
    len -= num_read;
    total_recved += num_read;
  }

  return total_recved;
}

//////////////////////////////////////////////////////////////////////////////

void broadcast(char *message, int skip_context_index)
{
  struct co_buffer_data_block *block = co_create_buffer_data_block(message, strlen(message));

  int i;

  printf("%s", message);

  for (i=0; i < num_contexts; i++)
  {
    struct co_buffer *buf;

    if (i == skip_context_index)
      continue;

    buf = (struct co_buffer *)malloc(sizeof(struct co_buffer));

    if (contexts[i]->write_buffer == NULL)
      contexts[i]->write_buffer = buf;
    else
    {
      struct co_buffer *prev_buf = contexts[i]->write_buffer;

      while (prev_buf->next != NULL)
        prev_buf = prev_buf->next;

      prev_buf->next = buf;
    }

    buf->data = block;
    buf->data_offset = 0;
    buf->next = NULL;

    block->references++;
  }
}

int read_line(SOCKET socket, char *line_buf, int max_chars)
{
  int i;

  for (i=0; i < max_chars; i++)
  {
    int result = co_recv(socket, line_buf + i, 1);

    if (result < 0)
      return result;

    if (((line_buf[i] == 10) && (i == 0)) // trailing end of CRLF
     || (line_buf[i] == 8)) // backspace
    {
      i--;
      continue;
    }

    if (line_buf[i] == 13)
    {
      i++;
      break;
    }
  }

  line_buf[i - 1] = 0;

  return i;
}

co_exit_type tcp_client_loop(SOCKET socket)
{
  char nickname[20];
  char line_buf[1000];

  int line_start_ofs;

  int status;

  status = co_send(socket, "Nickname: ", 10);

  if (status < 0)
    return 0;

  status = read_line(socket, nickname, 20);

  if (status < 0)
    return 0;

  line_buf[0] = '<';
  strcpy(line_buf + 1, nickname);
  strcat(line_buf, "> ");

  line_start_ofs = strlen(line_buf);

  while (true)
  {
    int status = read_line(socket, line_buf + line_start_ofs, 1000 - line_start_ofs - 2);

    if (status < 0)
      break;

    strcat(line_buf, "\r\n");

    broadcast(line_buf, -1);
  }

  return 0;
}

co_exit_type tcp_server_loop(SOCKET ignored_arg)
{
  struct sockaddr_in sin;
  socklen_t sin_len;
  SOCKET listen_socket;
  int yes = 1;

  ignored_arg; // suppress warnings that the argument is never used

  contexts = (struct co_context **)malloc(max_contexts * sizeof(struct co_context *));

  listen_socket = socket(AF_INET, SOCK_STREAM, 0);

  setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(PORT_NUMBER);
  if (bind(listen_socket, (struct sockaddr *)&sin, sizeof(sin)))
    return (co_exit_type)-1;

  if (listen(listen_socket, 5))
    return (co_exit_type)-1;

  while (true)
  {
    int i;
    struct fd_set want_read, want_write;

    SOCKET largest_socket;

    int num_found;

    FD_ZERO(&want_read);
    FD_ZERO(&want_write);

    FD_SET(listen_socket, &want_read);

    largest_socket = listen_socket;

    for (i=0; i < num_contexts; i++)
    {
      if (!contexts[i]->in_co_send) // prevent busy waiting :-)
        FD_SET(contexts[i]->socket, &want_read);

      if ((contexts[i]->write_buffer != NULL)
       && (contexts[i]->write_buffer_error_code == 0))
        FD_SET(contexts[i]->socket, &want_write);

      if (contexts[i]->socket > largest_socket)
        largest_socket = contexts[i]->socket;
    }

    num_found = select(largest_socket + 1, &want_read, &want_write, NULL, NULL);

    if (num_found == 0) // wtf?
      continue;

    if (FD_ISSET(listen_socket, &want_read))
    {
      SOCKET new_client;

      sin_len = sizeof(sin);
      new_client = accept(listen_socket, (struct sockaddr *)&sin, &sin_len);

      if (new_client >= 0)
        co_call_add(tcp_client_loop, new_client);
      // else ...

      num_found--;
    }

    // here we could backwards because contexts might get deleted
    // along the way and we don't want to skip any :-)
    for (i = num_contexts - 1; (i >= 0) && (num_found > 0); i--)
    {
      bool found = false;

      if (FD_ISSET(contexts[i]->socket, &want_read))
      {
        co_dispatch(contexts[i]);
        found = true;
      }

      if (FD_ISSET(contexts[i]->socket, &want_write))
      {
        int offset = contexts[i]->write_buffer->data_offset;
        char *buffer = contexts[i]->write_buffer->data->data + offset;
        int buffer_remaining = contexts[i]->write_buffer->data->data_length - offset;

        // only one 'send' is performed per call to 'select';
        // otherwise, it is impossible to guarantee that it
        // will not block.
        int num_written = send(contexts[i]->socket, buffer, buffer_remaining, 0);

        if (num_written < 0)
          contexts[i]->write_buffer_error_code = socketerror();
        else
        {
          buffer_remaining -= num_written;

          if (buffer_remaining == 0)
          {
            struct co_buffer *next = contexts[i]->write_buffer->next;

            co_release_buffer_data_block(contexts[i]->write_buffer->data);
            free(contexts[i]->write_buffer);
            contexts[i]->write_buffer = next;
          }
        }

        found = true;
      }

      if (found)
        num_found--;
    }

    for (i = num_contexts - 1; i >= 0; i--)
    {
      if (contexts[i]->in_co_send
       && ((contexts[i]->write_buffer == NULL)
        || (contexts[i]->write_buffer_error_code != 0)))
        co_dispatch(contexts[i]);

      if (contexts[i]->finished)
      {
        co_finish(contexts[i]);
        co_delete_context(contexts[i]);
      }
    }
  }

  return 0;
}

int main()
{
  struct co_context root;

#ifdef WIN32
  WSADATA wsadata;
  WSAStartup(0x202, &wsadata);

  root.ctx = ConvertThreadToFiber(NULL);
#endif // WIN32

  co_controller_context = co_current_context = &root;

  if (0 == setjmp(co_controller_context->exit))
  {
    co_controller_context->entrypoint = tcp_server_loop;
    co_controller_context->socket = (SOCKET)-1;
    co_controller_context->started = true;
    co_controller_context->finished = false;
    co_controller_context->write_buffer = NULL;
    co_controller_context->write_buffer_error_code = 0;
    
    co_controller_context->exit_code = co_controller_context->entrypoint(co_controller_context->socket);
  }

  co_controller_context->finished = true;

  return (int)co_controller_context->exit_code;
}


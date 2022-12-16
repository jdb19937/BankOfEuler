#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/fcntl.h>

#include "number.h"
#include "ctx.h"
#include "bank.h"
#include "server.h"
#include "client.h"

using namespace BankOfEuler;

void usage() {
  fprintf(stderr,
    "Usage: bankserve [options] [command]\n"
    "Options:\n"
    "  -h               this help\n"
    "  -d directory     use client and server configuration in this directory\n"
    "                   default is $BANKOFEULER_HOME, or else /usr/local/BankOfEuler\n"
    "Commands:\n"
    "  test             listen and log to console (default command)\n"
    "  start            detach, listen, and log to logs/bankserve.log\n"
    "  kill             kill server process if running\n"
    "  status           check if server is running\n"
    "  accept           handle connection on stdin/stdout (used by stunnel)\n"
  );
}

int _main(int argc, char **argv) {
  assert(argc);
  const char *prog = *argv;

  --argc;
  ++argv;

  bool la = 0;
  bool dt = 0;

  while (argc > 0 && **argv == '-') {
    if (!strcmp(*argv, "-d")) {
      --argc;
      ++argv;

      assert(argc);
      const char *home = *argv;

      --argc;
      ++argv;

      static char putenvstr[4096];
      snprintf(putenvstr, sizeof(putenvstr), "BANKOFEULER_HOME=%s", home);
      assert(0 == putenv(putenvstr));

      continue;
    }

    if (!strcmp(*argv, "-h")) {
      usage();
      return 0;
    }

    if (!strcmp(*argv, "--")) {
      --argc;
      ++argv;
      break;
    }
  }

  SCTX sctx;
  Server server(&sctx);
  std::string cmd;

  if (argc) {
    cmd = *argv;
    --argc;
    ++argv;
  } else
    cmd = "test";

  if (cmd == "accept") {
    assert(argc == 0);
    server.accept();
    return 0;
  }

  if (cmd == "status" || cmd == "kill") {
    assert(argc == 0);

    char pidfn[4096];
    snprintf(pidfn, sizeof(pidfn), "%s/logs/bankserve.pid", sctx.home.c_str());
    FILE *pidfp;
    pidfp = fopen(pidfn, "r");
    if (!pidfp) {
      fprintf(stderr, "%s: %s: %s\n", prog, pidfn, strerror(errno));
      fprintf(stderr, "bankserve is down\n");
      return 1;
    }

    char pidbuf[256];
    fgets(pidbuf, sizeof(pidbuf), pidfp);
    pid_t pid = atoi(pidbuf);
    fclose(pidfp);

    char cmdfn[4096];
    snprintf(cmdfn, sizeof(cmdfn), "/proc/%d/cmdline", pid);
    FILE *cmdfp;
    cmdfp = fopen(cmdfn, "r");
    if (!cmdfp) {
      fprintf(stderr, "%s: %s: %s\n", prog, cmdfn, strerror(errno));
      if (errno == ENOENT) {
        fprintf(stderr, "%s: unlinking %s\n", prog, pidfn);
        unlink(pidfn);
      }
      fprintf(stderr, "bankserve is down\n");
      return 1;
    }

    char cmdbuf[256];
    int cmdn = fread(cmdbuf, sizeof(char), sizeof(cmdbuf), cmdfp);
    assert(cmdn > 0);
    fclose(cmdfp);

    std::string z = std::string("", 1);
    std::string cmdbuf2 = std::string("stunnel") + z + sctx.home + "/bankserve.conf" + z;

    if (cmdn < cmdbuf2.length() || memcmp(cmdbuf, cmdbuf2.data(), cmdbuf2.length())) {
      fprintf(stderr, "%s: pid %d has wrong cmdline, someone has stolen our pid!\n", prog, pid);
      fprintf(stderr, "%s: unlinking %s\n", prog, pidfn);
      unlink(pidfn);
      fprintf(stderr, "bankserve is down\n");
      return 1;
    }

    if (cmd == "kill") {
      int ret = kill(pid, 9);
      fprintf(stderr, "%s: killling %d\n", prog, pid);
      if (ret < 0)
        fprintf(stderr, "%s: kill %d: %s\n", prog, pid, strerror(errno));
      fprintf(stderr, "%s: unlinking %s\n", prog, pidfn);
      unlink(pidfn);
      fprintf(stderr, "bankserve killed\n");
      return 0;
    }

    fprintf(stderr, "bankserve is up, stunnel pid %d\n", pid);
    return 0;
  }

  if (cmd == "start") {
    assert(argc == 0);

    char pidfn[4096];
    snprintf(pidfn, sizeof(pidfn), "%s/logs/bankserve.pid", sctx.home.c_str());
    int pidfd = open(pidfn, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (pidfd < 0) {
      fprintf(stderr, "%s: %s: %s\n", prog, pidfn, strerror(errno));
      if (errno == EEXIST)
        fprintf(stderr, "do you need to run bankserve kill?\n", prog);
      return 1;
    }

    char logfn[4096];

    snprintf(logfn, sizeof(logfn), "%s/logs/bankserve.log", sctx.home.c_str());
    int fd;
    assert(0 < (fd = open(logfn, O_RDWR | O_CREAT | O_APPEND, 0600)));

    fflush(stderr);
    assert(2 == dup2(fd, 2));
    close(fd);

    if (int pid = fork()) {
      char pidbuf[256];
      int pidn = sprintf(pidbuf, "%d\n", pid);
      assert(pidn == write(pidfd, pidbuf, pidn));
      close(pidfd);
      return 0;
    }
    close(pidfd);

    server.listen("bankserve.conf");
    return 0;
  }

  if (cmd == "test") {
    assert(argc == 0);

    // no log or pid file

    server.listen("bankserve.conf");
    return 0;
  }

  usage();
  return 1;
}

int main(int argc, char **argv) {
  try {
    return _main(argc, argv);
  } catch (const FailedAssertion &e) {
    fprintf(stderr, "%s\n", e.c_str());
  }

  fprintf(stderr, "bankserve: caught exception, aborting\n");
  return 1;
}

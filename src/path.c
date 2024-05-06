//
// Created by loumouli on 3/19/24.
//

#include "ft_strace.h"

char* check_path(char* path, char* arg) {
  char* full_path = calloc(4096, 1);
  if (full_path == NULL)
    return NULL;
  snprintf(full_path, 4096, "%s/%s", path, arg);
  return access(full_path, R_OK | X_OK) ? NULL : full_path;
}

char* get_path(char* arg) {
  const char* path_env = getenv("PATH");
  if (path_env == NULL) {
    fprintf(stderr, "Cant find path!\n");
    return NULL;
  }
  char** path = ft_split(path_env, ':');
  if (path == NULL) {
    fprintf(stderr, "split failed\n");
    return NULL;
  }
  if (access(arg, R_OK | X_OK) == 0)
    return arg;
  for (uint64_t idx = 0; path[idx]; ++idx) {
    char* tmp = check_path(path[idx], arg);
    if (tmp) {
      clean_array(path);
      return tmp;
    }
  }
  return NULL;
}

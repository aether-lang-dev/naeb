/* The commit the binary was built from and the checkout it was built in:
   ae/naeb/build_info/commit.h, which .build.ae writes (gitignored) before it
   builds; none without it. */
#if defined(__has_include)
#if __has_include("commit.h")
#include "commit.h"
#endif
#endif
#ifndef NAEB_COMMIT
#define NAEB_COMMIT ""
#endif
#ifndef NAEB_SRC
#define NAEB_SRC ""
#endif
const char *naeb_build_commit(void) { return NAEB_COMMIT; }
const char *naeb_build_source_dir(void) { return NAEB_SRC; }

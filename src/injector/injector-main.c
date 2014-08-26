#include "injector.h"

#include <shd-library.h>

static void _mylog(ShadowLogLevel level, const char* functionName, const char* format, ...) {
	va_list variableArguments;
	va_start(variableArguments, format);
	vprintf(format, variableArguments);
	va_end(variableArguments);
	printf("%s", "\n");
}

void bitcoindpreload_setPluginContext(PluginName plg) {
}
void bitcoindpreload_setShadowContext() {
}
void bitcoindpreload_setPthContext() {
}

extern int injector_new(int argc, char *argv[], ShadowLogFunc slogf);

int main(int argc, char *argv[]) { 
  injector_new(argc, argv, _mylog);
}

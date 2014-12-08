/*
 * See LICENSE for licensing information
 */

#ifndef PLUGIN_PRELOAD_H_
#define PLUGIN_PRELOAD_H_

typedef enum _ExecutionContext ExecutionContext;
enum _ExecutionContext {
  EXECTX_NONE, EXECTX_PLUGIN, EXECTX_PTH, EXECTX_SHADOW
};

typedef enum _PluginName PluginName;
enum _PluginName {
  PLUGIN_BITCOIND, PLUGIN_BITCOIND2
};

void bitcoindpreload_setPluginContext(PluginName plg);
void bitcoindpreload_setShadowContext();
void bitcoindpreload_setPthContext();
void bitcoindpreload_init(GModule *module, int nLocks);

#endif /* PLUGIN_PRELOAD_H_ */

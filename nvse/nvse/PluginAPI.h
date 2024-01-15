#pragma once

struct CommandInfo;
struct ParamInfo;
class TESObjectREFR;
class Script;
class TESForm;
struct ScriptEventList;
struct ArrayKey;
namespace PluginAPI { class ArrayAPI; }
struct PluginInfo;

typedef UInt32	PluginHandle;	// treat this as an opaque type

enum
{
	kPluginHandle_Invalid = 0xFFFFFFFF,
};

enum
{
	kInterface_Serialization = 0,
	kInterface_Console,

	// Added v0002
	kInterface_Messaging,
	kInterface_CommandTable,

	// Added v0004
	kInterface_StringVar,
	kInterface_ArrayVar,
	kInterface_Script,

	// Added v0005 - version bumped to 3
	kInterface_Data,
	// Added v0006
	kInterface_EventManager,

	kInterface_Max
};

struct ExpressionEvaluatorUtils;

struct NVSEInterface
{
	UInt32	nvseVersion;
	UInt32	runtimeVersion;
	UInt32	editorVersion;
	UInt32	isEditor;
	bool	(* RegisterCommand)(CommandInfo * info);	// returns true for success, false for failure
	void	(* SetOpcodeBase)(UInt32 opcode);
	void *	(* QueryInterface)(UInt32 id);

	// call during your Query or Load functions to get a PluginHandle uniquely identifying your plugin
	// invalid if called at any other time, so call it once and save the result
	PluginHandle	(* GetPluginHandle)(void);

	// CommandReturnType enum defined in CommandTable.h
	// does the same as RegisterCommand but includes return type; *required* for commands returning arrays
	// returns a full path the the game directory
	const char* (* GetRuntimeDirectory)();

	// Allows checking for nogore edition
	UInt32	isNogore;

	void		(*InitExpressionEvaluatorUtils)(ExpressionEvaluatorUtils *utils);
};

struct PluginInfo
{
	enum
	{
		kInfoVersion = 1
	};

	UInt32			infoVersion;
	const char *	name;
	UInt32			version;
};

typedef bool (* _NVSEPlugin_Query)(const NVSEInterface * nvse, PluginInfo * info);
typedef bool (* _NVSEPlugin_Load)(const NVSEInterface * nvse);
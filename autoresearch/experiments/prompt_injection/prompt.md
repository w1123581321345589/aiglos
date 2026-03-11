# Prompt Injection Detection

## Threat

A tool call that injects instructions designed to override the agent's original
system prompt, change its behavior, or make it execute actions outside its defined scope.

This includes:
- Direct injection in content fields ("Ignore previous instructions and...")
- Tool arguments that contain LLM directives disguised as data
- SOUL.md or MEMORY.md writes containing embedded instructions
- Shell execution arguments that construct new prompts

## Detection objective

The match function should return True when tool arguments contain:
- Classic injection phrases: "ignore previous", "forget your", "you are now",
  "disregard", "new instructions", "act as", "your new role"
- System prompt override attempts
- Instruction injection in content that will be read back into context
- Base64 or encoded versions of the above

## Important: minimize false positives

Do NOT flag:
- Security documentation that analyzes injection patterns (meta-discussion)
- Test files explicitly labeled as injection test cases
- User-facing content that discusses AI safety in general terms

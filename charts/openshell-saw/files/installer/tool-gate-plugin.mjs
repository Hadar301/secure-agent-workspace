// OpenClaw before_tool_call hook. Consequential tools come from
// tool-actions.yaml. This file does not list MCP servers or probe them.
import {
  AUDIT_PATH,
  IDENTITY_PATH,
  POLICY_PATH,
  TASK_PATH,
  evaluateToolCall,
  readJson,
  readText,
} from "./tool-gate.mjs";

// Replaced with the SHA-256 of the exact policy bytes when the host fills
// the read-only gate volume. No writable node_modules link is needed.
const EXPECTED_POLICY_HASH = "__SAW_POLICY_HASH__";

export function handleBeforeToolCall(event, ctx) {
  const taskFile = readJson(TASK_PATH);
  const result = evaluateToolCall({
    policyText: readText(POLICY_PATH),
    expectedPolicyHash: EXPECTED_POLICY_HASH,
    identity: readJson(IDENTITY_PATH),
    taskTitle: taskFile && typeof taskFile.title === "string" ? taskFile.title : "",
    toolName: event && event.toolName,
    params: event && event.params,
    sessionKey: (ctx && ctx.sessionKey) || (event && event.sessionKey) || "",
    sessionId: (ctx && ctx.sessionId) || (event && event.sessionId) || "",
    auditFile: AUDIT_PATH,
  });
  return result.hook;
}

export default {
  id: "saw-tool-gate",
  name: "SAW tool gate",
  description: "Audit every tool call with the signed-in user and current task, and require approval before consequential tools run.",
  register(api) {
    api.on("before_tool_call", (event, ctx) => handleBeforeToolCall(event, ctx));
  },
};

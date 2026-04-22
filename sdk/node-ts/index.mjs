// Auto-generated ESM wrapper for NAPI-RS CJS module.
import binding from "./index.cjs";

export const {
  EgressStream,
  ExecHandle,
  ExecOutput,
  ExecSink,
  FsReadStream,
  MetricsStream,
  Mount,
  NetworkPolicy,
  Sandbox,
  SandboxFs,
  SandboxHandle,
  Secret,
  Volume,
  VolumeHandle,
  allSandboxMetrics,
  install,
  isInstalled,
} = binding;

export { egressIntercept } from "./lib/egress-intercept.ts";

export default binding;

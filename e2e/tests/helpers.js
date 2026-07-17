import process from "node:process";
import path from "node:path";

// process.cwd() is e2e/ regardless of which cache subdir this file is loaded from
export const BIN = path.resolve(process.cwd(), "../zig-out/bin/a9s.exe");

// Env with fake AWS credentials — app skips auth prompt and shows home view.
export const envWithCreds = {
  ...process.env,
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  AWS_DEFAULT_REGION: "us-east-1",
};

// Env stripped of AWS vars and pointing home to a non-existent dir so neither
// env-var creds nor ~/.aws/credentials are found — app shows auth prompt.
export const envNoCreds = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !k.startsWith("AWS_"))
);
envNoCreds.USERPROFILE = "C:\\nonexistent-test-home-dir-a9s";
envNoCreds.HOME = "/nonexistent-test-home-dir-a9s";
envNoCreds.APPDATA = "C:\\nonexistent-test-home-dir-a9s";

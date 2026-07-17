import { defineConfig } from "@microsoft/tui-test";

export default defineConfig({
  timeout: 60000,
  expect: { timeout: 8000 },
  retries: 1,
  workers: 2,
});

import type { FullConfig, Reporter } from '@playwright/test/reporter';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Keep generated native test credentials out of Playwright failure snapshots. */
export default class PrivateArtifactsReporter implements Reporter {
  private directories: string[] = [];
  private secrets: string[] = [];
  onBegin(config: FullConfig) {
    this.directories = [...new Set(config.projects.map(project => project.outputDir))];
    const manifest = JSON.parse(readFileSync(process.env.REPAIR_E2E_MANIFEST!, 'utf8'));
    this.secrets = Object.values(manifest.users as Record<string, { password: string }>).map(user => user.password);
    for (const directory of this.directories) {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      chmodSync(directory, 0o700);
    }
  }
  onEnd() {
    const redact = (directory: string) => {
      if (!existsSync(directory)) return;
      chmodSync(directory, 0o700);
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) redact(path);
        else if (entry.isFile()) {
          chmodSync(path, 0o600);
          if (/\.(md|txt|json|xml|log)$/.test(path)) {
            let content = readFileSync(path, 'utf8');
            for (const secret of this.secrets) content = content.split(secret).join('[redacted test credential]');
            writeFileSync(path, content, { mode: 0o600 });
          }
        }
      }
    };
    for (const directory of this.directories) redact(directory);
  }
}

import Scanner from './scanner';
import { activeSources } from './lib/sources';

// Server component: counts sources here because opt-in API keys are server-only env vars.
export default function Home() {
  return <Scanner sourcesCount={activeSources().length} />;
}

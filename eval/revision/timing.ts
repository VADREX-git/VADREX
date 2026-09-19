// Evaluation-only active wall-clock timer. No production files are changed.
export class ActiveTimer {
  private activeSince: number | null = null;
  private activeMs = 0;
  private suspended = 0;
  private running = false;
  private began = 0;
  constructor(private readonly now: () => number = () => performance.now()) {}
  start(): void {
    if (this.running) throw new Error('timer already running');
    this.activeMs = 0; this.suspended = 0; this.running = true;
    this.began = this.now(); this.activeSince = this.began;
  }
  async outside<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.running) return operation();
    if (this.suspended++ === 0) {
      this.activeMs += this.now() - this.activeSince!;
      this.activeSince = null;
    }
    try { return await operation(); }
    finally {
      if (--this.suspended === 0) this.activeSince = this.now();
    }
  }
  finish(): { computeMs: number; invocationMs: number } {
    if (!this.running || this.suspended !== 0) throw new Error('timer not ready');
    const end = this.now();
    this.activeMs += end - this.activeSince!;
    this.running = false;
    return { computeMs: this.activeMs, invocationMs: end - this.began };
  }
}

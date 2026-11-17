/**
 * Lets at most `n` calls run at once; the rest wait their turn, and a call whose signal is aborted while it waits never starts.
 *
 * A browser keeps about six connections to one address, and the live event stream holds one of them. A page that asks about
 * every box at the same time (usage, self-test) can take all the rest while the boxes are slow, and then the call that says what
 * the server is waits in the browser's queue until its own timeout ends it. Keeping the per-box calls to a few at a time leaves
 * room for the calls that must not wait.
 */
export function createLimiter(n: number): <T>(run: () => Promise<T>, signal?: AbortSignal) => Promise<T> {
  let running = 0;
  const waiting: (() => void)[] = [];
  const next = () => {
    while (running < n && waiting.length > 0) {
      running += 1;
      waiting.shift()?.();
    }
  };
  return <T>(run: () => Promise<T>, signal?: AbortSignal) =>
    new Promise<T>((resolve, reject) => {
      const start = () => {
        if (signal?.aborted) {
          running -= 1;
          next();
          reject(new DOMException('aborted', 'AbortError'));
          return;
        }
        run().then(resolve, reject).finally(() => {
          running -= 1;
          next();
        });
      };
      waiting.push(start);
      next();
    });
}

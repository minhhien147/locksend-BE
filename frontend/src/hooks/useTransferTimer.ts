import { useEffect, useRef, useState } from "react";

/** Tick every 500ms while `active`; exposes stable start timestamp for transfer stats. */
export function useTransferTimer(active: boolean): {
  startedAt: number | null;
  tick: number;
} {
  const [tick, setTick] = useState(0);
  const startedAtRef = useRef<number | null>(null);

  useEffect(() => {
    if (!active) {
      startedAtRef.current = null;
      setTick(0);
      return;
    }

    if (startedAtRef.current === null) {
      startedAtRef.current = Date.now();
    }

    const id = window.setInterval(() => setTick((n) => n + 1), 500);
    return () => window.clearInterval(id);
  }, [active]);

  return {
    startedAt: active ? startedAtRef.current : null,
    tick,
  };
}

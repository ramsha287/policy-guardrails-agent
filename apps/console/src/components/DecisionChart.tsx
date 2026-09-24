// Requests per time bucket, stacked by decision.
// Mark specs: columns <= 24px wide, 4px rounded data-end (square at the baseline), 2px surface gap
// between stacked segments, hairline gridlines, one axis. The hover layer is one tooltip per column
// listing every decision; a table view carries the same numbers without hovering.

import { useLayoutEffect, useMemo, useRef, useState } from "react";

import { compact, niceScale } from "../lib/format";
import { DECISIONS, type Decision } from "../lib/types";
import { buildBuckets, type Bucket } from "./chartData";

const HEIGHT = 220;
const PAD = { top: 12, right: 12, bottom: 28, left: 44 };
const GAP = 2; // surface gap between stacked segments
const RADIUS = 4;

function topRounded(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, w / 2, h);
  return [
    `M${x},${y + h}`,
    `V${y + rr}`,
    `Q${x},${y} ${x + rr},${y}`,
    `H${x + w - rr}`,
    `Q${x + w},${y} ${x + w},${y + rr}`,
    `V${y + h}`,
    "Z",
  ].join(" ");
}

function bucketLabel(b: Bucket, unit: "hour" | "day"): string {
  const d = new Date(b.start);
  return unit === "hour"
    ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function DecisionChart({
  series,
  hours,
  unit,
  now,
}: {
  series: { bucket: string; decision: Decision; requests: number }[];
  hours: number;
  unit: "hour" | "day";
  now?: number;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [hover, setHover] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);

  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const update = () => setWidth(Math.max(280, el.clientWidth));
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const buckets = useMemo(() => buildBuckets(series, hours, unit, now), [series, hours, unit, now]);
  const present = DECISIONS.filter((d) => buckets.some((b) => b.counts[d] > 0));
  const legend = present.length > 0 ? present : DECISIONS;
  const maxTotal = Math.max(0, ...buckets.map((b) => b.total));
  const scale = niceScale(maxTotal);
  const plotW = width - PAD.left - PAD.right;
  const plotH = HEIGHT - PAD.top - PAD.bottom;
  const slot = plotW / Math.max(1, buckets.length);
  const barW = Math.max(2, Math.min(24, slot * 0.66));
  const y = (v: number) => PAD.top + plotH - (v / scale.max) * plotH;
  const ticks: number[] = [];
  for (let t = 0; t <= scale.max + 1e-9; t += scale.step) ticks.push(t);
  const labelEvery = Math.max(1, Math.ceil(buckets.length / Math.max(2, Math.floor(plotW / 72))));

  const hovered = hover !== null ? buckets[hover] : undefined;
  const tooltipLeft = hover !== null ? PAD.left + slot * hover + slot / 2 : 0;

  return (
    <div className="chart">
      <div className="chart-legend" aria-hidden="true">
        {legend.map((d) => (
          <span key={d} className="legend-item">
            <span className={`legend-swatch decision-${d}`} />
            {d}
          </span>
        ))}
        <button type="button" className="link-btn chart-table-toggle" onClick={() => setShowTable((v) => !v)}>
          {showTable ? "Show chart" : "Show table"}
        </button>
      </div>

      {showTable ? (
        <div className="table-wrap">
          <table className="table table-compact">
            <thead>
              <tr>
                <th scope="col">{unit === "hour" ? "Hour" : "Day"}</th>
                {DECISIONS.map((d) => (
                  <th key={d} scope="col" className="num">
                    {d}
                  </th>
                ))}
                <th scope="col" className="num">
                  total
                </th>
              </tr>
            </thead>
            <tbody>
              {buckets
                .filter((b) => b.total > 0)
                .map((b) => (
                  <tr key={b.start}>
                    <td>{bucketLabel(b, unit)}</td>
                    {DECISIONS.map((d) => (
                      <td key={d} className="num">
                        {b.counts[d]}
                      </td>
                    ))}
                    <td className="num">{b.total}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="chart-plot" ref={wrap} onPointerLeave={() => setHover(null)}>
          <svg
            width={width}
            height={HEIGHT}
            role="img"
            aria-label={`Requests per ${unit} by decision, last ${hours} hours. Peak ${maxTotal} requests.`}
          >
            {ticks.map((t) => (
              <g key={t}>
                <line className="grid" x1={PAD.left} x2={width - PAD.right} y1={y(t)} y2={y(t)} />
                <text className="axis-label" x={PAD.left - 8} y={y(t)} dy="0.32em" textAnchor="end">
                  {compact(t)}
                </text>
              </g>
            ))}
            <line className="baseline" x1={PAD.left} x2={width - PAD.right} y1={y(0)} y2={y(0)} />

            {buckets.map((b, i) => {
              const x = PAD.left + slot * i + (slot - barW) / 2;
              let acc = 0;
              const segs = DECISIONS.filter((d) => b.counts[d] > 0);
              return (
                <g key={b.start} className={hover === i ? "col col-hover" : "col"}>
                  {segs.map((d, si) => {
                    const v = b.counts[d];
                    const y0 = y(acc);
                    const y1 = y(acc + v);
                    acc += v;
                    const isTop = si === segs.length - 1;
                    const h = Math.max(1, y0 - y1 - (si > 0 ? GAP : 0));
                    const top = y1;
                    return isTop ? (
                      <path key={d} className={`seg decision-${d}`} d={topRounded(x, top, barW, h, RADIUS)} />
                    ) : (
                      <rect key={d} className={`seg decision-${d}`} x={x} y={top} width={barW} height={h} />
                    );
                  })}
                  {/* hit target: the whole slot, taller than the mark */}
                  <rect
                    className="hit"
                    x={PAD.left + slot * i}
                    y={PAD.top}
                    width={slot}
                    height={plotH}
                    tabIndex={b.total > 0 ? 0 : -1}
                    aria-label={`${bucketLabel(b, unit)}: ${b.total} requests`}
                    onPointerEnter={() => setHover(i)}
                    onFocus={() => setHover(i)}
                    onBlur={() => setHover(null)}
                  />
                </g>
              );
            })}

            {buckets.map((b, i) =>
              i % labelEvery === 0 ? (
                <text
                  key={b.start}
                  className="axis-label"
                  x={PAD.left + slot * i + slot / 2}
                  y={HEIGHT - 8}
                  textAnchor="middle"
                >
                  {bucketLabel(b, unit)}
                </text>
              ) : null,
            )}
          </svg>

          {hovered && (
            <div
              className="tooltip"
              style={{ left: Math.min(Math.max(tooltipLeft, 90), width - 90) }}
              role="presentation"
            >
              <p className="tooltip-title">{bucketLabel(hovered, unit)}</p>
              {DECISIONS.map((d) => (
                <p key={d} className="tooltip-row">
                  <span className={`tooltip-key decision-${d}`} />
                  <strong>{hovered.counts[d]}</strong>
                  <span className="muted">{d}</span>
                </p>
              ))}
              <p className="tooltip-row tooltip-total">
                <strong>{hovered.total}</strong>
                <span className="muted">total</span>
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
